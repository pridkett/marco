package querylog

import (
	"context"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/contract"
)

type Counts struct {
	Queries uint64
	Local   uint64
	Cache   uint64
	Misses  uint64
	Blocks  uint64
	Errors  uint64
}

type counters struct {
	queries atomic.Uint64
	local   atomic.Uint64
	cache   atomic.Uint64
	misses  atomic.Uint64
	blocks  atomic.Uint64
	errors  atomic.Uint64
}

func (c *counters) observe(event contract.Event) {
	c.queries.Add(1)
	switch event.Origin {
	case "local":
		c.local.Add(1)
	case "cache":
		c.cache.Add(1)
	case "policy":
		c.blocks.Add(1)
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
		Blocks: c.blocks.Load(), Errors: c.errors.Load(), Misses: c.misses.Load(),
	}
}

func (c *Counts) add(other Counts) {
	c.Queries += other.Queries
	c.Local += other.Local
	c.Cache += other.Cache
	c.Misses += other.Misses
	c.Blocks += other.Blocks
	c.Errors += other.Errors
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
	Client   string
	Question string
	Outcome  string
	After    time.Time
	Until    time.Time
	BeforeID int64
	Limit    int
}

type Entry struct {
	ID      int64
	Time    time.Time
	Node    string
	Client  string
	Name    string
	Type    uint16
	RCode   int
	Origin  string
	Reason  string
	Rule    string
	Cache   string
	Latency time.Duration
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
		clauses = append(clauses, "client = ?")
		args = append(args, f.Client)
	}
	if f.Question != "" {
		clauses = append(clauses, "instr(name, ?) > 0")
		args = append(args, strings.ToLower(f.Question))
	}
	if f.Outcome != "" {
		rcode, found := dns.StringToRcode[strings.ToUpper(f.Outcome)]
		if !found {
			rcode = -1
		}
		clauses = append(clauses, "(origin = ? OR reason = ? OR rcode = ?)")
		args = append(args, f.Outcome, f.Outcome, rcode)
	}
	if !f.Until.IsZero() {
		clauses = append(clauses, "time < ?")
		args = append(args, f.Until.UnixNano())
	}
	if f.BeforeID > 0 {
		clauses = append(clauses, "id < ?")
		args = append(args, f.BeforeID)
	}
	if f.Limit <= 0 || f.Limit > 200 {
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
