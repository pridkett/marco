package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/migrate"
	"github.com/pridkett/marco/internal/runtime"
	"github.com/pridkett/marco/internal/store"
)

func TestOfflineMigrationBackupAndRestore(t *testing.T) {
	dir := t.TempDir()
	deployment := filepath.Join(dir, "marco.json")
	writeTestFile(t, deployment, `{"node":"fixture","dataDir":"live","dns":{"listen":["127.0.0.1:1053"],"allow":["127.0.0.1/32"]},"history":{"enabled":false}}`)
	powerDNS := filepath.Join(dir, "legacy.db")
	db, err := sql.Open("sqlite", powerDNS)
	if err != nil {
		t.Fatal(err)
	}
	sqlFixture, err := os.ReadFile("testdata/hostnames.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(sqlFixture)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	flags := []string{"migrate", "--config", deployment, "--scraper", "testdata/scraper.toml",
		"--powerdns", powerDNS, "--adguard", "testdata/adguard.yaml", "--disposition", "testdata/disposition.json"}
	var result bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	run := func(args ...string) string {
		t.Helper()
		result.Reset()
		if err := command(ctx, args, &result); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, result.String())
		}
		return result.String()
	}
	preview := run(flags...)
	var report migrate.Report
	if err := json.Unmarshal([]byte(preview), &report); err != nil {
		t.Fatal(err)
	}
	if report.Base != 1 || len(report.Unsupported) != 2 || len(report.Staged) != 2 ||
		!strings.Contains(preview, "retired alias retired.split.test") || !strings.Contains(preview, "kept explicit owner server.split.test") {
		t.Fatalf("unexpected preview %s", preview)
	}
	live := filepath.Join(dir, "live")
	if _, err := os.Stat(live); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry-run created live data: %v", err)
	}
	if err := command(ctx, append(flags, "--apply", "--base", "1"), &result); err == nil {
		t.Fatal("unreviewed unsupported settings were applied")
	}
	applied := run(append(flags, "--apply", "--base", "1", "--allow-unsupported")...)
	if !strings.Contains(applied, `"appliedRevision": 2`) {
		t.Fatal(applied)
	}
	again := run(append(flags, "--apply", "--base", "2", "--allow-unsupported")...)
	if !strings.Contains(again, `"appliedRevision": 2`) {
		t.Fatal(again)
	}
	if err := command(ctx, append(flags, "--apply", "--base", "1", "--allow-unsupported"), &result); !errors.Is(err, store.ErrStale) {
		t.Fatalf("wanted a stale preview error, got %v", err)
	}
	exported := run("export", "--config", deployment)
	if strings.Contains(exported, "legacy-") || strings.Contains(exported, "co-authored") {
		t.Fatal("portable export includes instance state")
	}
	inventory := run("export", "--config", deployment, "--inventory")
	if !strings.Contains(inventory, `"legacyOwner": "laptop.split.test."`) {
		t.Fatalf("legacy observation unavailable in inventory export: %s", inventory)
	}

	d, err := config.ReadDeployment(deployment)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := newCompiler(d)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := store.Open(ctx, live, config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := runtime.Open(ctx, manager, compiler)
	if err != nil {
		t.Fatal(err)
	}
	local := publisher.View().Local
	if chain := local.Lookup("server-ui.split.test.", dns.TypeA); len(chain.Answer) != 3 {
		t.Fatalf("imported CNAME chain: %+v", chain)
	}
	if address := local.Lookup("laptop.split.test.", dns.TypeA); len(address.Answer) != 1 {
		t.Fatalf("legacy address: %+v", address)
	}
	if suppressed := local.Lookup("power.split.test.", dns.TypeA); !suppressed.Suppressed || suppressed.Code != dns.RcodeNameError {
		t.Fatalf("paired suppression: %+v", suppressed)
	}
	if retired := local.Lookup("retired.split.test.", dns.TypeCNAME); retired.Found {
		t.Fatalf("retired alias: %+v", retired)
	}
	_, err = publisher.Update(ctx, 2, func(state *config.State) error {
		state.Desired.Records = state.Desired.Records[:1]
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	publisher.Close()
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	run(append(flags, "--apply", "--base", "3", "--allow-unsupported")...)
	if updated := run("export", "--config", deployment); strings.Contains(updated, "server-ui.split.test") {
		t.Fatalf("re-import replaced an admin deletion: %s", updated)
	}
	backup := filepath.Join(dir, "backup")
	run("backup", "--config", deployment, "--output", backup)
	restored := filepath.Join(dir, "target.json")
	writeTestFile(t, restored, `{"node":"restored","dataDir":"restored","dns":{"listen":["127.0.0.1:1053"],"allow":["127.0.0.1/32"]}}`)
	run("restore", "--config", restored, "--backup", backup)
	if state := run("validate", "--config", restored); !strings.Contains(state, "revision 3") {
		t.Fatal(state)
	}
	if again := run("export", "--config", restored, "--inventory"); again != inventory {
		t.Fatalf("restored inventory differs: %s", again)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
