package store

import (
	"context"
	"database/sql"
	"sync/atomic"
	"time"
)

type auditKey struct{}

type ChangeAudit struct {
	account   string
	operation string
	saved     atomic.Bool
}

// WithChangeAudit records the authenticated actor with a DNS revision commit.
func WithChangeAudit(ctx context.Context, account, operation string) (context.Context, *ChangeAudit) {
	event := &ChangeAudit{account: account, operation: operation}
	return context.WithValue(ctx, auditKey{}, event), event
}

func (event *ChangeAudit) Saved() bool { return event != nil && event.saved.Load() }

func WriteAudit(ctx context.Context, tx *sql.Tx, account, operation, result string, revision uint64) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO admin_audit(time, account, operation, result, revision) VALUES (?, ?, ?, ?, ?)
	`, time.Now().Unix(), account, operation, result, revision)
	return err
}
