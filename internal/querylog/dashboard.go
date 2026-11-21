package querylog

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

type ActivityPoint struct {
	Time time.Time `json:"time"`
	Counts
}

// restoreRecent seeds the rolling counters before the DNS listeners start.
// Current queries then update these buckets even if individual history rows drop.
func (l *Log) restoreRecent(ctx context.Context, now time.Time) error {
	oldest := now.Truncate(time.Minute).Add(-time.Duration(len(l.recent)-1) * time.Minute)
	rows, err := l.writer.QueryContext(ctx, `
		SELECT time / ? AS minute, COUNT(*), SUM(origin = 'local'), SUM(origin = 'cache' OR cache = 'hit'),
			SUM(cache = 'miss'), SUM(origin = 'policy'), SUM(reason = ?), SUM(rcode = ?), SUM(latency)
		FROM dns_queries WHERE time >= ? AND time <= ? GROUP BY minute
	`, int64(time.Minute), UpstreamBlocked, dns.RcodeServerFailure, oldest.UnixNano(), now.UnixNano())
	if err != nil {
		return err
	}
	defer rows.Close()
	var restored []*bucket
	for rows.Next() {
		var minute, latency int64
		var c Counts
		if err := rows.Scan(&minute, &c.Queries, &c.Local, &c.Cache, &c.Misses, &c.Blocks, &c.UpstreamBlocks,
			&c.Errors, &latency); err != nil {
			return err
		}
		b := &bucket{minute: minute}
		b.counts.queries.Store(c.Queries)
		b.counts.local.Store(c.Local)
		b.counts.cache.Store(c.Cache)
		b.counts.misses.Store(c.Misses)
		b.counts.blocks.Store(c.Blocks)
		b.counts.upstream.Store(c.UpstreamBlocks)
		b.counts.errors.Store(c.Errors)
		b.counts.latency.Store(int64(time.Duration(latency) * time.Microsecond))
		restored = append(restored, b)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, b := range restored {
		l.recent[b.minute%int64(len(l.recent))].Store(b)
	}
	return nil
}

// Activity groups the same in-memory counters used by Stats into
// consecutive intervals, including intervals that received no queries.
func (l *Log) Activity(now time.Time, window, interval time.Duration) ([]ActivityPoint, Counts) {
	end := now.UTC().Truncate(time.Minute).Add(time.Minute)
	start := end.Add(-window)
	points := make([]ActivityPoint, window/interval)
	var total Counts
	for i := range points {
		at := start.Add(time.Duration(i) * interval)
		points[i].Time = at
		for minute := at.Unix() / 60; minute < at.Add(interval).Unix()/60; minute++ {
			if minute < 0 {
				continue
			}
			b := l.recent[minute%int64(len(l.recent))].Load()
			if b != nil && b.minute == minute {
				points[i].Counts.add(b.counts.read())
			}
		}
		total.add(points[i].Counts)
	}
	return points, total
}

type RankedEntry struct {
	Value string `json:"value"`
	Count uint64 `json:"count"`
}

type Rankings struct {
	Clients []RankedEntry `json:"clients"`
	Domains []RankedEntry `json:"domains"`
	Blocked []RankedEntry `json:"blocked"`
	// UpstreamBlocked ranks names an upstream resolver blocked.
	UpstreamBlocked []RankedEntry `json:"upstreamBlocked"`
}

// TopQueries ranks retained history. Client keys have already passed through the
// query log's configured anonymization before reaching this query.
func (l *Log) TopQueries(ctx context.Context, from, until time.Time) (Rankings, error) {
	var top Rankings
	if !l.settings.Enabled {
		return top, nil
	}
	if cutoff := until.Add(-l.settings.Retention); cutoff.After(from) {
		from = cutoff
	}
	for _, group := range []struct {
		column, condition string
		dst               *[]RankedEntry
	}{
		{"client", "client <> ''", &top.Clients},
		{"name", "name <> ''", &top.Domains},
		{"name", "name <> '' AND origin = 'policy'", &top.Blocked},
		{"name", "name <> '' AND reason = '" + UpstreamBlocked + "'", &top.UpstreamBlocked},
	} {
		results, err := l.rank(ctx, group.column, group.condition, from, until)
		if err != nil {
			return Rankings{}, err
		}
		*group.dst = results
	}
	return top, nil
}

func (l *Log) rank(ctx context.Context, column, condition string, from, until time.Time) ([]RankedEntry, error) {
	rows, err := l.db.QueryContext(ctx, `
		SELECT `+column+`, COUNT(*) AS queries FROM dns_queries
		WHERE time >= ? AND time <= ? AND `+condition+`
		GROUP BY `+column+` ORDER BY queries DESC, `+column+` ASC LIMIT 5
	`, from.UnixNano(), until.UnixNano())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []RankedEntry
	for rows.Next() {
		var entry RankedEntry
		if err := rows.Scan(&entry.Value, &entry.Count); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}
