package store

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pridkett/marco/internal/contract"
)

// Blocking publishes a durable pause to all DNS listeners without a database
// read on the DNS path. A paused resolver checks the deadline on every query.
type Blocking struct {
	store *Store
	mu    sync.Mutex
	pause atomic.Pointer[contract.BlockingPause]
}

func (s *Store) OpenBlocking(ctx context.Context) (*Blocking, error) {
	b := &Blocking{store: s}
	var until sql.NullInt64
	err := s.db.QueryRowContext(ctx, "SELECT until_ns FROM blocking_pause WHERE id=1").Scan(&until)
	if errors.Is(err, sql.ErrNoRows) {
		return b, nil
	}
	if err != nil {
		return nil, err
	}
	pause := contract.BlockingPause{Paused: true}
	if until.Valid {
		pause.Until = time.Unix(0, until.Int64).UTC()
	}
	b.pause.Store(&pause)
	return b, nil
}

func (b *Blocking) Status(now time.Time) contract.BlockingPause {
	if pause := b.pause.Load(); pause != nil {
		return pause.At(now)
	}
	return contract.BlockingPause{}
}

func (b *Blocking) Set(ctx context.Context, account string, pause contract.BlockingPause) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	err := b.store.Write(ctx, func(tx *sql.Tx) error {
		operation := "resume-blocking"
		if pause.Paused {
			operation = "pause-blocking"
			var until any
			if !pause.Until.IsZero() {
				until = pause.Until.UnixNano()
			}
			if _, err := tx.ExecContext(ctx, "INSERT OR REPLACE INTO blocking_pause VALUES(1, ?)", until); err != nil {
				return err
			}
		} else if _, err := tx.ExecContext(ctx, "DELETE FROM blocking_pause WHERE id=1"); err != nil {
			return err
		}
		var revision uint64
		if err := tx.QueryRowContext(ctx, "SELECT revision FROM dns_state WHERE id=1").Scan(&revision); err != nil {
			return err
		}
		return WriteAudit(ctx, tx, account, operation, "success", revision)
	})
	if err != nil {
		return err
	}
	b.pause.Store(&pause)
	return nil
}
