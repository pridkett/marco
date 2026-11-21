package querylog

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/contract"
)

func logEvent(at time.Time, name string) contract.Event {
	return contract.Event{
		Input: contract.Input{
			Name: name, Type: dns.TypeAAAA, Class: dns.ClassINET,
			Peer: netip.MustParseAddr("2001:db8::1234"), Time: at,
		},
		Result: contract.Result{
			RCode: dns.RcodeNameError, Origin: "policy", Reason: "service", Rule: "fixture", Cache: "hit",
		},
		Node: "test-node", Latency: 2 * time.Millisecond,
	}
}

func TestDisabledStillCounts(t *testing.T) {
	l, err := Open("", Settings{})
	if err != nil {
		t.Fatal(err)
	}
	l.Observe(logEvent(time.Now(), "filtered.test."))
	stats := l.Stats()
	if stats.Enabled || stats.Total.Queries != 1 || stats.Total.Blocks != 1 || stats.Total.Cache != 1 ||
		stats.Recent["15 minutes"].Queries != 1 || stats.Total.CacheHitRate() != "100.0%" || stats.Dropped != 0 {
		t.Fatalf("unexpected counts: %+v", stats)
	}
	if page, err := l.Search(t.Context(), Filter{}); err != nil || len(page.Entries) > 0 {
		t.Fatalf("disabled search: %+v %v", page, err)
	}
}

func TestHistoryFiltersAnonymizationAndRetention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.sqlite")
	cfg := Settings{Enabled: true, Retention: time.Hour, Anonymize: true, AnonymizationKey: []byte("test-anonymization-key")}
	l, err := Open(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	l.Observe(logEvent(now.Add(-2*time.Hour), "expired.test."))
	l.Observe(logEvent(now.Add(-10*time.Minute), "filtered-old.test."))
	l.Observe(logEvent(now.Add(-5*time.Minute), "filtered-new.test."))
	l.Observe(logEvent(now, "something-else.test."))
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	l, err = Open(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	points, counts := l.Activity(now, 15*time.Minute, time.Minute)
	if len(points) != 15 || counts.Queries != 3 || counts.Blocks != 3 || counts.Cache != 3 ||
		counts.AverageLatency() != "2.00 ms" || l.Stats().Total.Queries != 0 {
		t.Fatalf("retained activity did not restore the rolling counters: %+v", counts)
	}
	top, err := l.TopQueries(t.Context(), now.Add(-6*time.Minute), now)
	if err != nil || len(top.Clients) != 1 || top.Clients[0].Count != 2 ||
		!strings.HasPrefix(top.Clients[0].Value, "client-") || len(top.Domains) != 2 ||
		len(top.Blocked) != 2 || top.Blocked[0].Value != "filtered-new.test." {
		t.Fatalf("unexpected recent rankings: %+v (%v)", top, err)
	}
	page, err := l.Search(t.Context(), Filter{Question: "FILTERED", Outcome: "NXDOMAIN", Until: now, Limit: 1})
	if err != nil || len(page.Entries) != 1 || page.Next == 0 {
		t.Fatalf("first page: %+v %v", page, err)
	}
	got := page.Entries[0]
	if got.Name != "filtered-new.test." || got.Client != l.ClientID(netip.MustParseAddr("2001:db8::1234")) || got.TypeLabel() != "AAAA" ||
		got.RCodeLabel() != "NXDOMAIN" || got.Cache != "hit" || got.Latency != 2*time.Millisecond {
		t.Fatalf("invalid entry: %+v", got)
	}
	page, err = l.Search(t.Context(), Filter{Client: got.Client, Question: "filtered", Outcome: "service", Until: now, BeforeID: page.Next})
	if err != nil || len(page.Entries) != 1 || page.Entries[0].Name != "filtered-old.test." || page.Next != 0 {
		t.Fatalf("second page: %+v %v", page, err)
	}
	page, err = l.Search(t.Context(), Filter{Question: "expired"})
	if err != nil || len(page.Entries) != 0 {
		t.Fatalf("expired row returned: %+v %v", page, err)
	}
	wire, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(wire), "2001:db8::1234") {
		t.Fatal("raw peer persisted")
	}
}

func TestUpstreamBlocksAreCountedApartFromPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upstream.sqlite")
	cfg := Settings{Enabled: true, Retention: time.Hour}
	l, err := Open(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	upstreamBlock := func(at time.Time, name, origin string) contract.Event {
		event := logEvent(at, name)
		event.Result = contract.Result{
			RCode: dns.RcodeSuccess, Origin: origin, Reason: UpstreamBlocked,
			Rule: "Blocked by NextDNS: blocklist:fixture", Cache: "miss",
		}
		return event
	}
	allowed := logEvent(now.Add(-time.Minute), "allowed.test.")
	allowed.Result = contract.Result{RCode: dns.RcodeSuccess, Origin: "upstream", Reason: "upstream-answer", Rule: "allow-rule", Cache: "miss"}
	l.Observe(upstreamBlock(now.Add(-3*time.Minute), "tracker.test.", "upstream"))
	l.Observe(upstreamBlock(now.Add(-2*time.Minute), "tracker.test.", "cache"))
	l.Observe(upstreamBlock(now.Add(-2*time.Minute), "other-tracker.test.", "upstream"))
	l.Observe(logEvent(now.Add(-time.Minute), "filtered.test."))
	l.Observe(allowed)
	if c := l.Stats().Total; c.UpstreamBlocks != 3 || c.Blocks != 1 || c.Queries != 5 {
		t.Fatalf("live counts: %+v", c)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	l, err = Open(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, c := l.Activity(now, 15*time.Minute, time.Minute); c.UpstreamBlocks != 3 || c.Blocks != 1 {
		t.Fatalf("restored counts: %+v", c)
	}
	top, err := l.TopQueries(t.Context(), now.Add(-10*time.Minute), now)
	if err != nil || len(top.UpstreamBlocked) != 2 || top.UpstreamBlocked[0] != (RankedEntry{"tracker.test.", 2}) ||
		len(top.Blocked) != 1 || top.Blocked[0].Value != "filtered.test." {
		t.Fatalf("rankings: %+v (%v)", top, err)
	}
	var indexes int
	if err := l.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index'
		AND name IN ('dns_queries_policy', 'dns_queries_upstream_blocked')`).Scan(&indexes); err != nil || indexes != 2 {
		t.Fatalf("ranking indexes: %d (%v)", indexes, err)
	}
	for _, outcome := range []string{"upstream blocked", "Upstream-Blocked"} {
		page, err := l.Search(t.Context(), Filter{Outcome: outcome})
		if err != nil || len(page.Entries) != 3 {
			t.Fatalf("%q search: %+v %v", outcome, page, err)
		}
		for _, entry := range page.Entries {
			if !entry.UpstreamBlocked() || entry.AllowedByRule() {
				t.Fatalf("upstream block reported as allowed: %+v", entry)
			}
		}
	}
	page, err := l.Search(t.Context(), Filter{Outcome: "allowed"})
	if err != nil || len(page.Entries) != 1 || page.Entries[0].Name != "allowed.test." {
		t.Fatalf("allowed search included upstream blocks: %+v %v", page, err)
	}
	page, err = l.Search(t.Context(), Filter{Outcome: "blocked"})
	if err != nil || len(page.Entries) != 1 || page.Entries[0].Name != "filtered.test." {
		t.Fatalf("policy block search: %+v %v", page, err)
	}
}

// A day of history can take seconds to rank on a Raspberry Pi. Rankings that
// outlast the dashboard's deadline must finish in the background and be served
// afterwards, rather than being cancelled and restarted on every page load.
func TestSlowRankingsFinishAfterTheCallerGivesUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "slow.sqlite")
	cfg := Settings{Enabled: true, Retention: time.Hour}
	l, err := Open(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	l.Observe(logEvent(now.Add(-time.Minute), "slow.test."))
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if l, err = Open(path, cfg); err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	release := make(chan struct{})
	var refreshes atomic.Int32
	l.rankHook = func() {
		refreshes.Add(1)
		<-release
	}
	impatient := func(until time.Time) (Rankings, error) {
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		return l.TopQueries(ctx, until.Add(-15*time.Minute), until)
	}

	if _, err := impatient(now); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cold rankings returned %v, want the caller's deadline", err)
	}
	if _, err := impatient(now); !errors.Is(err, context.DeadlineExceeded) || refreshes.Load() != 1 {
		t.Fatalf("second caller did not join the running refresh: %v, %d refreshes", err, refreshes.Load())
	}
	close(release)
	top, err := l.TopQueries(t.Context(), now.Add(-15*time.Minute), now)
	if err != nil || len(top.Blocked) != 1 || top.Blocked[0].Value != "slow.test." {
		t.Fatalf("finished refresh was not served: %+v %v", top, err)
	}
	if _, err := impatient(now.Add(30 * time.Second)); err != nil || refreshes.Load() != 1 {
		t.Fatalf("fresh rankings were not reused: %v, %d refreshes", err, refreshes.Load())
	}

	release = make(chan struct{})
	defer close(release)
	stale, err := impatient(now.Add(2 * time.Minute))
	if err != nil || len(stale.Blocked) != 1 || refreshes.Load() != 2 {
		t.Fatalf("stale rankings were not served during a refresh: %+v %v, %d refreshes", stale, err, refreshes.Load())
	}
	// A 15-minute ranking from an hour ago no longer describes the window.
	if _, err := impatient(now.Add(time.Hour)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hour-old rankings were served for a 15-minute window: %v", err)
	}
}

func TestHistoryBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "budget.sqlite")
	l, err := Open(path, Settings{Enabled: true, Queue: 512, MaxBytes: minMaxBytes})
	if err != nil {
		t.Fatal(err)
	}
	for range 500 {
		e := logEvent(time.Now(), strings.Repeat("z", 255))
		e.Node = strings.Repeat("n", 128)
		e.Reason = strings.Repeat("r", 64)
		e.Rule = strings.Repeat("r", 128)
		e.Origin = strings.Repeat("o", 32)
		e.Cache = strings.Repeat("c", 32)
		l.Observe(e)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if stats := l.Stats(); stats.Dropped != 0 {
		t.Fatalf("history unable to keep writing at its budget: %+v", stats)
	}
	var bytes int64
	for _, path := range []string{path, path + "-wal", path + "-shm"} {
		stat, err := os.Stat(path)
		if err == nil {
			bytes += stat.Size()
		}
	}
	if bytes > minMaxBytes {
		t.Fatalf("history uses %d bytes, budget is %d", bytes, minMaxBytes)
	}
	l, err = Open(path, Settings{Enabled: true, MaxBytes: minMaxBytes})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	page, err := l.Search(t.Context(), Filter{Limit: 200})
	if err != nil || len(page.Entries) == 0 || len(page.Entries) >= 200 {
		t.Fatalf("history capacity did not expire older entries: %d %v", len(page.Entries), err)
	}
}

func TestOverflowAndStoragePressure(t *testing.T) {
	// A full queue is deterministic without a consumer. Observe must neither
	// wait nor lose its aggregate counters.
	full := &Log{settings: Settings{Enabled: true}, pending: make(chan contract.Event, 1), stop: make(chan struct{})}
	full.Observe(logEvent(time.Now(), "fixture.test."))
	full.Observe(logEvent(time.Now(), "fixture.test."))
	if stats := full.Stats(); stats.Dropped != 1 || stats.Total.Queries != 2 {
		t.Fatalf("queue overflow was missed: %+v", stats)
	}

	path := filepath.Join(t.TempDir(), "read-only.sqlite")
	l, err := Open(path, Settings{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := l.writer.ExecContext(ctx, "PRAGMA query_only = ON"); err != nil {
		t.Fatal(err)
	}
	l.Observe(logEvent(time.Now(), "fixture.test."))
	_ = l.Close()
	if stats := l.Stats(); stats.Dropped != 1 || stats.Total.Queries != 1 || stats.Error == "" {
		t.Fatalf("storage failure was missed: %+v", stats)
	}
}
