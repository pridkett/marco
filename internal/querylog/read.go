package querylog

import (
	"context"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
)

type Counts struct {
	Queries uint64 `json:"queries"`
	Local   uint64 `json:"local"`
	Cache   uint64 `json:"cacheHits"`
	Misses  uint64 `json:"cacheMisses"`
	Blocks  uint64 `json:"blocks"`
	// UpstreamBlocks counts answers an upstream resolver marked as blocked.
	// They are not included in Blocks, which counts Marco's own policy.
	UpstreamBlocks uint64        `json:"upstreamBlocks"`
	Errors         uint64        `json:"errors"`
	Latency        time.Duration `json:"latencyNanoseconds"`
}

// UpstreamBlocked is the reason recorded when an upstream resolver blocked a query.
const UpstreamBlocked = "upstream-blocked"

type counters struct {
	queries  atomic.Uint64
	local    atomic.Uint64
	cache    atomic.Uint64
	misses   atomic.Uint64
	blocks   atomic.Uint64
	upstream atomic.Uint64
	errors   atomic.Uint64
	latency  atomic.Int64
}

func (c *counters) observe(event contract.Event) {
	c.queries.Add(1)
	c.latency.Add(int64(event.Latency))
	switch event.Origin {
	case "local":
		c.local.Add(1)
	case "cache":
		c.cache.Add(1)
	case "policy":
		c.blocks.Add(1)
	}
	if event.Reason == UpstreamBlocked {
		c.upstream.Add(1)
	}
	if event.Cache == "hit" && event.Origin != "cache" {
		c.cache.Add(1)
	}
	if event.Cache == "miss" {
		c.misses.Add(1)
	}
	if event.RCode == dns.RcodeServerFailure {
		c.errors.Add(1)
	}
}

func (c *counters) read() Counts {
	return Counts{
		Queries: c.queries.Load(), Local: c.local.Load(), Cache: c.cache.Load(),
		Blocks: c.blocks.Load(), UpstreamBlocks: c.upstream.Load(), Errors: c.errors.Load(), Misses: c.misses.Load(),
		Latency: time.Duration(c.latency.Load()),
	}
}

func (c *Counts) add(other Counts) {
	c.Queries += other.Queries
	c.Local += other.Local
	c.Cache += other.Cache
	c.Misses += other.Misses
	c.Blocks += other.Blocks
	c.UpstreamBlocks += other.UpstreamBlocks
	c.Errors += other.Errors
	c.Latency += other.Latency
}

func (c Counts) AverageLatency() string {
	if c.Queries == 0 {
		return "—"
	}
	return strconv.FormatFloat(float64(c.Latency)/float64(time.Millisecond)/float64(c.Queries), 'f', 2, 64) + " ms"
}

func (c Counts) CacheHitRate() string {
	if c.Cache+c.Misses == 0 {
		return "—"
	}
	return strconv.FormatFloat(float64(c.Cache)*100/float64(c.Cache+c.Misses), 'f', 1, 64) + "%"
}

type bucket struct {
	minute int64
	counts counters
}

type Stats struct {
	Enabled bool
	Dropped uint64
	Error   string
	Total   Counts
	Recent  map[string]Counts
}

func (l *Log) Stats() Stats {
	now := time.Now().Unix() / 60
	stats := Stats{
		Enabled: l.settings.Enabled, Dropped: l.dropped.Load(), Total: l.stats.read(),
		Recent: make(map[string]Counts, 3),
	}
	if last := l.lastErr.Load(); last != nil {
		stats.Error = *last
	}
	var short, hour, day Counts
	for i := range l.recent {
		b := l.recent[i].Load()
		if b == nil || b.minute > now || now-b.minute >= 1440 {
			continue
		}
		count := b.counts.read()
		day.add(count)
		if now-b.minute < 60 {
			hour.add(count)
		}
		if now-b.minute < 15 {
			short.add(count)
		}
	}
	stats.Recent["15 minutes"], stats.Recent["1 hour"], stats.Recent["24 hours"] = short, hour, day
	return stats
}

type Filter struct {
	Client   string // One or more comma-separated IPs or client IDs.
	Question string
	Type     *uint16 // Nil matches every DNS question type.
	Outcome  string
	After    time.Time
	Until    time.Time
	BeforeID int64
	Limit    int // Callers bound the page size. Zero uses 50 entries.
}

type Entry struct {
	ID      int64         `json:"id"`
	Time    time.Time     `json:"time"`
	Node    string        `json:"node"`
	Client  string        `json:"client"`
	Name    string        `json:"name"`
	Type    uint16        `json:"type"`
	RCode   int           `json:"rcode"`
	Origin  string        `json:"origin"`
	Reason  string        `json:"reason,omitempty"`
	Rule    string        `json:"rule,omitempty"`
	Cache   string        `json:"cache,omitempty"`
	Latency time.Duration `json:"latencyNanoseconds"`
}

func (e Entry) TypeLabel() string {
	if name := dns.TypeToString[e.Type]; name != "" {
		return name
	}
	return "TYPE" + strconv.Itoa(int(e.Type))
}

func (e Entry) RCodeLabel() string {
	if name := dns.RcodeToString[e.RCode]; name != "" {
		return name
	}
	return strconv.Itoa(e.RCode)
}

// Resolved entries only carry a rule reference when an allow rule matched or,
// for upstream blocks, to hold the upstream's reason.
func (e Entry) AllowedByRule() bool {
	return e.Rule != "" && e.Reason != UpstreamBlocked &&
		(e.Origin == "local" || e.Origin == "cache" || e.Origin == "upstream")
}

// UpstreamBlocked reports whether an upstream resolver blocked this query.
func (e Entry) UpstreamBlocked() bool { return e.Reason == UpstreamBlocked }

type Page struct {
	Entries []Entry
	Next    int64
}

func (l *Log) Search(ctx context.Context, f Filter) (Page, error) {
	if !l.settings.Enabled {
		return Page{}, nil
	}
	clauses := []string{"time >= ?"}
	cutoff := time.Now().Add(-l.settings.Retention)
	if f.After.After(cutoff) {
		cutoff = f.After
	}
	args := []any{cutoff.UnixNano()}
	if f.Client != "" {
		clients := strings.Split(f.Client, ",")
		clauses = append(clauses, "client IN (?"+strings.Repeat(", ?", len(clients)-1)+")")
		for _, client := range clients {
			args = append(args, strings.TrimSpace(client))
		}
	}
	if f.Question != "" {
		clauses = append(clauses, "instr(name, ?) > 0")
		args = append(args, strings.ToLower(f.Question))
	}
	if f.Type != nil {
		clauses = append(clauses, "type = ?")
		args = append(args, *f.Type)
	}
	switch outcome := strings.ToLower(strings.TrimSpace(f.Outcome)); outcome {
	case "":
	case "allowed":
		clauses = append(clauses, "(rule <> '' AND reason <> ? AND origin IN ('local', 'cache', 'upstream') AND rcode IN (?, ?))")
		args = append(args, UpstreamBlocked, dns.RcodeSuccess, dns.RcodeNameError)
	default:
		switch outcome {
		case "blocked":
			outcome = "policy"
		case "upstream blocked", "upstream block":
			outcome = UpstreamBlocked
		case "cache hit":
			outcome = "cache"
		case "local dns":
			outcome = "local"
		}
		rcode, found := dns.StringToRcode[strings.ToUpper(outcome)]
		if !found {
			rcode = -1
		}
		clauses = append(clauses, "(origin = ? OR reason = ? OR rcode = ?)")
		args = append(args, outcome, outcome, rcode)
	}
	if !f.Until.IsZero() {
		clauses = append(clauses, "time < ?")
		args = append(args, f.Until.UnixNano())
	}
	if f.BeforeID > 0 {
		clauses = append(clauses, "id < ?")
		args = append(args, f.BeforeID)
	}
	if f.Limit <= 0 || f.Limit > config.MaxManagementPageSize {
		f.Limit = 50
	}
	args = append(args, f.Limit+1)
	rows, err := l.db.QueryContext(ctx, `
		SELECT id, time, node, client, name, type, rcode, origin, reason, rule, cache, latency
		FROM dns_queries WHERE `+strings.Join(clauses, " AND ")+` ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return Page{}, err
	}
	defer rows.Close()
	var result Page
	for rows.Next() {
		var entry Entry
		var ts, latency int64
		if err := rows.Scan(&entry.ID, &ts, &entry.Node, &entry.Client, &entry.Name, &entry.Type, &entry.RCode,
			&entry.Origin, &entry.Reason, &entry.Rule, &entry.Cache, &latency); err != nil {
			return Page{}, err
		}
		entry.Time = time.Unix(0, ts)
		entry.Latency = time.Duration(latency) * time.Microsecond
		result.Entries = append(result.Entries, entry)
	}
	if len(result.Entries) > f.Limit {
		result.Entries = result.Entries[:f.Limit]
		result.Next = result.Entries[f.Limit-1].ID
	}
	return result, rows.Err()
}
