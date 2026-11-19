package main

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/auth"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/dnsserver"
	"github.com/pridkett/marco/internal/filter"
	"github.com/pridkett/marco/internal/inventory"
	"github.com/pridkett/marco/internal/runtime"
	"github.com/pridkett/marco/internal/store"
)

func TestPublicationSurvivesFailedUpdatesAndRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	root := t.TempDir()
	path := filepath.Join(root, "list.txt")
	writeTestFile(t, path, "||old.test^\n")
	desired := config.Defaults()
	desired.Records = []config.Record{
		{Name: "server.home.arpa", Type: "A", Value: "192.0.2.2"},
		{Name: "alias.home.arpa", Type: "CNAME", Value: "server.home.arpa"},
	}
	desired.Zones = []config.Zone{{Name: "home.arpa", Private: true, Publish: true}}
	desired.Subscriptions = map[string]config.Subscription{"fixture": {File: "list.txt", Enabled: true}}
	directory := filepath.Join(root, "state")
	db, err := store.Open(ctx, directory, desired)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	compiler, err := newCompiler(config.Deployment{ListDir: root})
	if err != nil {
		t.Fatal(err)
	}
	p, err := runtime.Open(ctx, db, compiler)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	worker := filter.NewWorker(p, filter.NewFetcher(root), 24*time.Hour)
	workers, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		worker.Run(workers)
	}()
	defer func() { stop(); <-done }()

	assertBlocked := func(pub *runtime.Publisher, name string, blocked bool) {
		t.Helper()
		policies := pub.View().Policies
		sel := policies.Select(netip.MustParseAddr("192.0.2.101"), time.Now())
		if decision := policies.External(sel, name, time.Now()); decision.Blocked != blocked {
			t.Fatalf("%s = %+v, want blocked=%t", name, decision, blocked)
		}
	}
	refresh := func(want string) {
		t.Helper()
		old := worker.Status()[0].Attempt
		if err := worker.Trigger("fixture"); err != nil {
			t.Fatal(err)
		}
		until := time.NewTimer(2 * time.Second)
		defer until.Stop()
		poll := time.NewTicker(5 * time.Millisecond)
		defer poll.Stop()
		for {
			status := worker.Status()[0]
			if status.Attempt.After(old) && strings.Contains(status.Error, want) && (want != "" || status.Error == "") {
				return
			}
			select {
			case <-until.C:
				t.Fatalf("refresh did not finish with %q: %+v", want, status)
			case <-poll.C:
			}
		}
	}
	if got := worker.Status()[0].State; got != "staged" {
		t.Fatalf("required list state = %q", got)
	}
	assertBlocked(p, "old.test.", false)
	refresh("")
	assertBlocked(p, "old.test.", true)
	good := p.Revision()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	refresh("no such file")
	if p.Revision() != good {
		t.Fatal("failed fetch published a revision")
	}
	assertBlocked(p, "old.test.", true)
	for _, tc := range []struct{ body, want string }{
		{"", "no usable rules"}, {"||new.test^\n/a.*/\n", "regular expression"},
	} {
		writeTestFile(t, path, tc.body)
		refresh(tc.want)
		if p.Revision() != good {
			t.Fatal("failed parse published a revision")
		}
		assertBlocked(p, "old.test.", true)
		assertBlocked(p, "new.test.", false)
	}
	sql := func(statement string) {
		t.Helper()
		if err := db.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, statement)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	sql(`CREATE TRIGGER reject_dns BEFORE UPDATE ON dns_state BEGIN SELECT RAISE(ABORT, 'simulated disk write failure'); END`)
	writeTestFile(t, path, "||new.test^\n")
	refresh("simulated disk write failure")
	if p.Revision() != good {
		t.Fatal("failed database commit published a revision")
	}
	assertBlocked(p, "old.test.", true)
	sql("DROP TRIGGER reject_dns")

	start := make(chan struct{})
	var group sync.WaitGroup
	group.Go(func() {
		<-start
		if err := worker.Trigger("fixture"); err != nil {
			t.Error(err)
		}
	})
	group.Go(func() {
		<-start
		_, err := p.Update(ctx, 0, func(state *config.State) error {
			return inventory.Reconcile(state, inventory.Snapshot{Controller: "fixture", Site: "home", Complete: true, ObservedAt: time.Now().UTC()})
		})
		if err != nil {
			t.Error(err)
		}
	})
	group.Go(func() {
		<-start
		for attempt := 0; attempt < 4; attempt++ {
			_, err := p.Update(ctx, p.Revision(), func(state *config.State) error {
				state.Desired.Records = state.Desired.Records[:1]
				return nil
			})
			if !errors.Is(err, store.ErrStale) {
				if err != nil {
					t.Error(err)
				}
				return
			}
		}
		t.Error("admin edit could not apply after retry")
	})
	close(start)
	group.Wait()
	refresh("")
	assertDNSNegative(t, p)
	restarted, err := runtime.Open(ctx, db, compiler)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if state := restarted.Snapshot(); state.SitePolls["fixture/home"].IsZero() || len(state.Desired.Records) != 1 {
		t.Fatalf("lost concurrent update on restart: %+v", state)
	}
	assertBlocked(restarted, "old.test.", false)
	assertBlocked(restarted, "new.test.", true)
	assertDNSNegative(t, restarted)
	_, err = p.Update(ctx, p.Revision(), func(s *config.State) error {
		source := s.Desired.Subscriptions["fixture"]
		source.AllowEmpty = true
		s.Desired.Subscriptions["fixture"] = source
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, "")
	refresh("")
	assertBlocked(p, "new.test.", false)
	if artifact := p.Snapshot().Artifacts["fixture"]; artifact.Digest == "" || artifact.RuleCount != 0 {
		t.Fatalf("explicitly empty artifact not saved: %+v", artifact)
	}
}

func assertDNSNegative(t *testing.T, publisher *runtime.Publisher) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	server, err := dnsserver.Listen(dnsserver.Options{Address: "127.0.0.1:0",
		Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, View: publisher.View})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)
	client := dns.Client{Net: "udp", Timeout: time.Second}
	query := new(dns.Msg).SetQuestion("alias.home.arpa.", dns.TypeA)
	reply, _, err := client.Exchange(query, server.Address())
	if err != nil || reply == nil || reply.Rcode != dns.RcodeNameError || len(reply.Answer) != 0 {
		t.Fatalf("deleted alias returned %+v, %v", reply, err)
	}
}

func TestRevisionAndAuditCommitTogether(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	db, err := store.Open(ctx, t.TempDir(), config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := auth.New(ctx, db, auth.Settings{PublicURL: "https://admin.test",
		Issuer: "https://identity.test", ClientID: "fixture", AdminGroup: "admin"}); err != nil {
		t.Fatal(err)
	}
	compiler, err := newCompiler(config.Deployment{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := runtime.Open(ctx, db, compiler)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	update := func(s *config.State) error {
		s.Desired.Default.Mode = config.DenyAll
		return nil
	}
	sql := func(statement string) {
		t.Helper()
		if err := db.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, statement)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	sql(`CREATE TRIGGER reject_audit BEFORE INSERT ON admin_audit BEGIN SELECT RAISE(ABORT, 'simulated audit failure'); END`)
	auditCtx, audit := store.WithChangeAudit(ctx, "local:operator", "edit-policies")
	if revision, err := p.Update(auditCtx, 1, update); err == nil || revision != 1 || audit.Saved() || p.Revision() != 1 {
		t.Fatalf("audit failure published revision %d: %v", revision, err)
	}
	sql("DROP TRIGGER reject_audit")
	if revision, err := p.Update(auditCtx, 1, update); err != nil || revision != 2 || !audit.Saved() {
		t.Fatalf("could not publish audited revision %d: %v", revision, err)
	}
	var count int
	if err := db.DB().QueryRowContext(ctx, `SELECT count(*) FROM admin_audit
		WHERE account='local:operator' AND operation='edit-policies' AND result='success' AND revision=2`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("want one durable audit record, got %d: %v", count, err)
	}
}
