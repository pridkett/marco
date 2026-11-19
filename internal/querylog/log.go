// Package querylog records bounded DNS history off the request path.
package querylog

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pridkett/marco/internal/contract"

	_ "modernc.org/sqlite"
)

const (
	DefaultMaxBytes  = 128 << 20
	DefaultRetention = 7 * 24 * time.Hour
	defaultQueue     = 1024
	batchSize        = 128
	pageSize         = 4096
	minMaxBytes      = 256 << 10
	metadataReserve  = 64 << 10
)

type Settings struct {
	Enabled          bool
	Anonymize        bool
	Queue            int
	MaxBytes         int64
	Retention        time.Duration
	AnonymizationKey []byte
}

type Log struct {
	db       *sql.DB
	writer   *sql.Conn
	pending  chan contract.Event
	stop     chan struct{}
	stopped  chan struct{}
	close    sync.Once
	closeErr error

	settings Settings
	maxPages int64
	stats    counters
	dropped  atomic.Uint64
	recent   [1440]atomic.Pointer[bucket]
	lastErr  atomic.Pointer[string]
}

func Open(path string, cfg Settings) (*Log, error) {
	log := &Log{settings: cfg}
	if !cfg.Enabled {
		return log, nil
	}
	if cfg.Anonymize && len(cfg.AnonymizationKey) < 16 {
		return nil, errors.New("query history anonymization requires a key of at least 16 bytes")
	}
	if cfg.Queue <= 0 {
		cfg.Queue = defaultQueue
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = DefaultMaxBytes
	}
	if cfg.Retention <= 0 {
		cfg.Retention = DefaultRetention
	}
	if cfg.MaxBytes < minMaxBytes {
		return nil, fmt.Errorf("query history needs a budget of at least %d bytes", minMaxBytes)
	}
	cfg.AnonymizationKey = append([]byte(nil), cfg.AnonymizationKey...)
	log.settings = cfg

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dsn := url.URL{Scheme: "file", Path: abs, RawQuery: "_pragma=busy_timeout%28100%29"}
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(3)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	writer, err := db.Conn(ctx)
	if err != nil {
		db.Close()
		return nil, err
	}
	log.db, log.writer = db, writer
	if err := log.init(ctx); err != nil {
		writer.Close()
		db.Close()
		return nil, fmt.Errorf("initialize query history: %w", err)
	}
	log.pending = make(chan contract.Event, cfg.Queue)
	log.stop, log.stopped = make(chan struct{}), make(chan struct{})
	go log.run()
	return log, nil
}

func (l *Log) init(ctx context.Context) error {
	// Reserve equal space for main pages and a WAL transaction, plus room for
	// frame headers and the shared-memory index. Keep spill disabled so each
	// changed page appears in the WAL at most once per transaction.
	pages := (l.settings.MaxBytes - metadataReserve) / pageSize * 45 / 100
	_, err := l.writer.ExecContext(ctx, fmt.Sprintf(`
		PRAGMA page_size = %d;
		PRAGMA auto_vacuum = INCREMENTAL;
		PRAGMA journal_mode = WAL;
		PRAGMA wal_autocheckpoint = 0;
		PRAGMA journal_size_limit = 0;
		PRAGMA cache_spill = OFF;
		PRAGMA max_page_count = %d;
		CREATE TABLE IF NOT EXISTS dns_queries (
			id INTEGER PRIMARY KEY AUTOINCREMENT, time INTEGER NOT NULL, node TEXT NOT NULL,
			client TEXT NOT NULL, name TEXT NOT NULL, type INTEGER NOT NULL, rcode INTEGER NOT NULL,
			origin TEXT NOT NULL, reason TEXT NOT NULL, rule TEXT NOT NULL, cache TEXT NOT NULL,
			latency INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS dns_queries_time ON dns_queries(time);
	`, pageSize, pages))
	if err != nil {
		return err
	}
	var effective, actualPageSize int64
	if err := l.writer.QueryRowContext(ctx, "PRAGMA max_page_count").Scan(&effective); err != nil {
		return err
	}
	if err := l.writer.QueryRowContext(ctx, "PRAGMA page_size").Scan(&actualPageSize); err != nil {
		return err
	}
	if effective != pages || actualPageSize != pageSize {
		return errors.New("existing query history does not fit its configured page budget")
	}
	l.maxPages = effective
	return l.flush(ctx, nil)
}

// Observe records statistics and offers individual events without waiting for
// disk, a database lock, or a receiver.
func (l *Log) Observe(event contract.Event) {
	if event.Time.IsZero() {
		event.Time = time.Now()
	}
	l.stats.observe(event)
	minute := event.Time.Unix() / 60
	if minute >= 0 {
		slot := &l.recent[minute%int64(len(l.recent))]
		for {
			b := slot.Load()
			if b != nil && b.minute >= minute {
				if b.minute == minute {
					b.counts.observe(event)
				}
				break
			}
			if slot.CompareAndSwap(b, &bucket{minute: minute}) {
				continue
			}
		}
	}

	if !l.settings.Enabled {
		return
	}
	select {
	case <-l.stop:
	case l.pending <- event:
		return
	default:
	}
	l.dropped.Add(1)
}

func (l *Log) run() {
	defer close(l.stopped)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	batch := make([]contract.Event, 0, int(min(int64(batchSize), l.settings.MaxBytes/8192)))
	write := func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := l.flush(ctx, batch); err != nil {
			l.dropped.Add(uint64(len(batch)))
			// SQLite errors may include addresses, names, and local paths.
			message := "Query history storage is unavailable."
			l.lastErr.Store(&message)
		} else {
			l.lastErr.Store(nil)
		}
		clear(batch)
		batch = batch[:0]
	}
	for {
		select {
		case event := <-l.pending:
			batch = append(batch, event)
			if len(batch) == cap(batch) {
				write()
			}
		case <-tick.C:
			write()
		case <-l.stop:
			for {
				select {
				case event := <-l.pending:
					batch = append(batch, event)
					if len(batch) == cap(batch) {
						write()
					}
				default:
					if len(batch) != 0 {
						write()
					}
					return
				}
			}
		}
	}
}

func (l *Log) checkpoint(ctx context.Context) error {
	var busy, pages, checkpointed int
	err := l.writer.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &pages, &checkpointed)
	if err == nil && busy != 0 {
		return errors.New("query history readers are holding the WAL")
	}
	return err
}

func (l *Log) flush(ctx context.Context, batch []contract.Event) error {
	if err := l.checkpoint(ctx); err != nil {
		return err
	}
	tx, err := l.writer.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	cutoff := time.Now().Add(-l.settings.Retention).UnixNano()
	if _, err := tx.ExecContext(ctx, "DELETE FROM dns_queries WHERE time < ?", cutoff); err != nil {
		return err
	}
	if err := l.makeRoom(ctx, tx, len(batch)); err != nil {
		return err
	}
	if len(batch) > 0 {
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO dns_queries(time, node, client, name, type, rcode, origin, reason, rule, cache, latency)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, e := range batch {
			if e.Time.UnixNano() < cutoff {
				continue
			}
			if _, err := stmt.ExecContext(ctx, e.Time.UnixNano(), limitText(e.Node, 128), l.client(e), limitText(e.Name, 255),
				e.Type, e.RCode, limitText(e.Origin, 32), limitText(e.Reason, 64), limitText(e.Rule, 128), limitText(e.Cache, 32),
				e.Latency.Microseconds()); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// makeRoom evicts the oldest rows when actual page usage nears the SQLite
// ceiling. A batch reserves enough space for its longest permitted entries,
// index pages, and page splits.
func (l *Log) makeRoom(ctx context.Context, tx *sql.Tx, batch int) error {
	reserve := int64(4 + (batch*960+pageSize-1)/pageSize)
	const usage = `SELECT page_count - freelist_count FROM pragma_page_count(), pragma_freelist_count()`
	for range 8 {
		var pages int64
		if err := tx.QueryRowContext(ctx, usage).Scan(&pages); err != nil {
			return err
		}
		if pages+reserve <= l.maxPages {
			return nil
		}
		result, err := tx.ExecContext(ctx, `DELETE FROM dns_queries WHERE id IN (
			SELECT id FROM dns_queries ORDER BY id LIMIT ?
		)`, max(32, batch*4))
		if err != nil {
			return err
		}
		deleted, err := result.RowsAffected()
		if err != nil || deleted == 0 {
			return err
		}
	}
	return nil
}

func (l *Log) client(e contract.Event) string {
	if !e.Peer.IsValid() {
		return ""
	}
	ip := e.Peer.Unmap().String()
	if !l.settings.Anonymize {
		return ip
	}
	digest := hmac.New(sha256.New, l.settings.AnonymizationKey)
	digest.Write([]byte(ip))
	return "client-" + hex.EncodeToString(digest.Sum(nil)[:12])
}

func limitText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

func (l *Log) Close() error {
	if !l.settings.Enabled {
		return nil
	}
	l.close.Do(func() {
		close(l.stop)
		<-l.stopped
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		l.closeErr = errors.Join(l.checkpoint(ctx), l.writer.Close(), l.db.Close())
	})
	return l.closeErr
}
