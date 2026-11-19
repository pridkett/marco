package querylog

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
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
		stats.Recent["15 minutes"].Queries != 1 || stats.Dropped != 0 {
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
	page, err := l.Search(t.Context(), Filter{Question: "FILTERED", Outcome: "NXDOMAIN", Until: now, Limit: 1})
	if err != nil || len(page.Entries) != 1 || page.Next == 0 {
		t.Fatalf("first page: %+v %v", page, err)
	}
	got := page.Entries[0]
	if got.Name != "filtered-new.test." || !strings.HasPrefix(got.Client, "client-") || got.TypeLabel() != "AAAA" ||
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
