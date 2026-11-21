package querylog

import (
	"context"
	"log/slog"
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

const (
	// rankingMaxAge is how long a window's rankings are reused before a
	// request starts a refresh.
	rankingMaxAge = time.Minute
	// rankingTimeout bounds one background refresh. A day of history takes a
	// few seconds to rank on a Raspberry Pi, far longer than a page waits.
	rankingTimeout = 30 * time.Second
)

type rankingEntry struct {
	result  Rankings
	until   time.Time     // End of the window the result covers. Zero until the first success.
	pending chan struct{} // Closed when the running refresh finishes. Nil when idle.
	err     error         // Most recent refresh failure.
}

// TopQueries ranks retained history between from and until. Results are cached
// per window length for up to a minute. When a refresh outlasts ctx, the
// refresh keeps running in the background and the previous result, if any, is
// returned instead. Client keys have already passed through the query log's
// configured anonymization before reaching this query.
func (l *Log) TopQueries(ctx context.Context, from, until time.Time) (Rankings, error) {
	if !l.settings.Enabled {
		return Rankings{}, nil
	}
	// Dashboard windows start on a minute boundary and end now, so their length
	// drifts within a minute. Rounding up keeps one cache entry per range.
	window := (until.Sub(from) + time.Minute - 1).Truncate(time.Minute)
	l.rankMu.Lock()
	entry := l.ranks[window]
	if entry == nil {
		entry = &rankingEntry{}
		l.ranks[window] = entry
	}
	if !entry.until.IsZero() && !until.Before(entry.until) && until.Sub(entry.until) < rankingMaxAge {
		result := entry.result
		l.rankMu.Unlock()
		return result, nil
	}
	if entry.pending == nil {
		entry.pending = make(chan struct{})
		go l.refreshRankings(entry, from, until)
	}
	pending := entry.pending
	l.rankMu.Unlock()

	select {
	case <-pending:
	case <-ctx.Done():
	}
	l.rankMu.Lock()
	defer l.rankMu.Unlock()
	// Serve the previous result while a refresh runs, unless it is too old to
	// describe the window, such as an hour-old ranking of the last 15 minutes.
	if !entry.until.IsZero() && until.Sub(entry.until) < max(window/4, 2*rankingMaxAge) {
		return entry.result, nil
	}
	if entry.err != nil {
		return Rankings{}, entry.err
	}
	return Rankings{}, ctx.Err()
}

func (l *Log) refreshRankings(entry *rankingEntry, from, until time.Time) {
	ctx, cancel := context.WithTimeout(l.rankCtx, rankingTimeout)
	defer cancel()
	if l.rankHook != nil {
		l.rankHook()
	}
	result, err := l.computeRankings(ctx, from, until)
	if err != nil && l.rankCtx.Err() == nil {
		slog.Warn("could not rank query history", "error", err)
	}
	l.rankMu.Lock()
	defer l.rankMu.Unlock()
	if err == nil {
		entry.result, entry.until, entry.err = result, until, nil
	} else {
		entry.err = err
	}
	close(entry.pending)
	entry.pending = nil
}

// computeRankings runs the ranking queries one at a time, so a refresh holds at
// most one of the history's read connections and the query log stays usable.
func (l *Log) computeRankings(ctx context.Context, from, until time.Time) (Rankings, error) {
	var top Rankings
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
