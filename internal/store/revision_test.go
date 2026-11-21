package store

import (
	"errors"
	"testing"
	"time"

	"github.com/pridkett/marco/internal/config"
)

func TestWriteGenerationUpgradeAndFreshnessCAS(t *testing.T) {
	ctx := t.Context()
	path := t.TempDir()
	db, err := Open(ctx, path, config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	initial, err := db.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	base := initial
	base.Revision++
	base.Generation++
	base.Desired.Default.Mode = config.LocalOnly
	if err := db.Save(ctx, initial, base); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(ctx, "ALTER TABLE dns_state DROP COLUMN generation; PRAGMA user_version=2;"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	old, err := Inspect(ctx, path)
	if err != nil || old.Generation != base.Revision || old.Revision != base.Revision {
		t.Fatalf("inspect legacy database: revision=%d generation=%d error=%v", old.Revision, old.Generation, err)
	}
	db, err = Open(ctx, path, config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	upgraded, err := db.Load(ctx)
	if err != nil || upgraded.Generation != base.Generation || upgraded.Revision != base.Revision ||
		upgraded.Desired.Default.Mode != config.LocalOnly {
		t.Fatalf("upgrade lost settings or counters: revision=%d generation=%d error=%v", upgraded.Revision, upgraded.Generation, err)
	}
	updated := upgraded
	updated.Generation++
	updated.SitePolls = map[string]time.Time{"fixture/site": time.Now().UTC()}
	if err := db.Save(ctx, upgraded, updated); err != nil {
		t.Fatal(err)
	}
	if err := db.Save(ctx, upgraded, updated); !errors.Is(err, ErrStale) {
		t.Fatalf("old generation could overwrite newer metadata at the same applied revision: %v", err)
	}
	current, err := db.Load(ctx)
	if err != nil || current.Revision != upgraded.Revision || current.Generation != updated.Generation ||
		!current.SitePolls["fixture/site"].Equal(updated.SitePolls["fixture/site"]) {
		t.Fatalf("metadata write was not durable: revision=%d generation=%d error=%v", current.Revision, current.Generation, err)
	}
}
