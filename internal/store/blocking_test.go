package store_test

import (
	"testing"
	"time"

	"github.com/pridkett/marco/internal/auth"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
	"github.com/pridkett/marco/internal/store"
)

func TestBlockingPausePersistsAndExpires(t *testing.T) {
	ctx, dir := t.Context(), t.TempDir()
	open := func() *store.Store {
		t.Helper()
		db, err := store.Open(ctx, dir, config.Defaults())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}
	load := func(db *store.Store) *store.Blocking {
		t.Helper()
		blocking, err := db.OpenBlocking(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return blocking
	}

	db := open()
	if _, err := auth.New(ctx, db, auth.Settings{
		PublicURL: "https://marco.test", Issuer: "https://id.test", ClientID: "fixture",
	}); err != nil {
		t.Fatal(err)
	}
	// Opening a version-one database must retain its configuration and start active.
	if _, err := db.DB().ExecContext(ctx, "ALTER TABLE dns_state DROP COLUMN generation; DROP TABLE blocking_pause; PRAGMA user_version=1;"); err != nil {
		t.Fatal(err)
	}
	db = open()
	blocking := load(db)
	now := time.Now()
	until := now.Add(time.Minute)
	if blocking.Status(now).Paused {
		t.Fatal("new resolver starts paused")
	}
	account := "local:operator"
	if err := blocking.Set(ctx, account, contract.BlockingPause{Paused: true, Until: until}); err != nil {
		t.Fatal(err)
	}
	blocking = load(open())
	if got := blocking.Status(now); !got.Paused || !got.Until.Equal(until) {
		t.Fatalf("timed pause did not survive restart: %+v", got)
	}
	if blocking.Status(until).Paused {
		t.Fatal("blocking did not resume at the deadline")
	}

	if err := blocking.Set(ctx, account, contract.BlockingPause{Paused: true}); err != nil {
		t.Fatal(err)
	}
	blocking = load(open())
	if got := blocking.Status(until.Add(7 * 24 * time.Hour)); !got.Paused || !got.Until.IsZero() {
		t.Fatalf("indefinite pause expired: %+v", got)
	}
	if err := blocking.Set(ctx, account, contract.BlockingPause{}); err != nil {
		t.Fatal(err)
	}
	if load(open()).Status(now).Paused {
		t.Fatal("manual resume did not survive restart")
	}
	var events int
	if err := db.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_audit
		WHERE account = ? AND operation IN ('pause-blocking', 'resume-blocking') AND result = 'success' AND revision = 1
	`, account).Scan(&events); err != nil || events != 3 {
		t.Fatalf("expected three audited changes, got %d: %v", events, err)
	}
}
