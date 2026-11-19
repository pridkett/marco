package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/migrate"
	"github.com/pridkett/marco/internal/runtime"
	"github.com/pridkett/marco/internal/store"
)

func migrateCommand(ctx context.Context, args []string, out io.Writer) error {
	flags, file := deploymentFlags("migrate")
	var options migrate.Options
	flags.StringVar(&options.DesiredPath, "desired", "", "versioned Marco desired configuration JSON")
	flags.StringVar(&options.StatePath, "inventory", "", "separate Marco device state JSON")
	flags.StringVar(&options.ScraperPath, "scraper", "", "rendered, redacted UniFi scraper TOML")
	flags.StringVar(&options.PowerDNSPath, "powerdns", "", "consistent SQLite backup of hostnames.db")
	flags.StringVar(&options.AdGuardPath, "adguard", "", "sanitized AdGuard YAML")
	flags.BoolVar(&options.ReplaceDesired, "replace-settings", false, "explicitly replace the entire desired config")
	decisions := flags.String("disposition", "", "JSON with operator selections, retired aliases, and service/upstream mappings")
	skip := flags.Bool("allow-unsupported", false, "explicitly accept the previewed unsupported items")
	apply := flags.Bool("apply", false, "apply offline; omit to preview read-only")
	base := flags.Uint64("base", 0, "base revision from the preview, required for --apply")
	d, err := loadDeployment(flags, file, args)
	if err != nil {
		return err
	}
	if *decisions != "" {
		if err := config.ReadJSON(*decisions, &options.Disposition); err != nil {
			return err
		}
	}
	if options.DesiredPath == "" && options.StatePath == "" && options.ScraperPath == "" &&
		options.PowerDNSPath == "" && options.AdGuardPath == "" && *decisions == "" {
		return errors.New("supply at least one migration input or disposition")
	}
	if *apply {
		if *base == 0 {
			return errors.New("applying an import requires the --base revision from its preview")
		}
		lock, err := store.Lock(d.DataDir)
		if err != nil {
			return err
		}
		defer lock.Close()
	}
	candidate, err := readState(ctx, d)
	if err != nil {
		return err
	}
	if *apply && *base != candidate.Revision {
		return fmt.Errorf("%w: current revision is %d", store.ErrStale, candidate.Revision)
	}
	identity, err := migrate.Fingerprint(options, *skip)
	if err != nil {
		return err
	}
	var report migrate.Report
	if _, exists := candidate.Imports[identity]; exists {
		report = migrate.Report{Base: candidate.Revision, Warnings: []migrate.Item{
			{Source: "migration", Detail: "this input and disposition were already applied; kept current settings"},
		}}
		if *apply {
			report.Applied = candidate.Revision
		}
		return writeJSON(out, report)
	}
	report, err = migrate.Build(&candidate, options)
	if err != nil {
		return err
	}
	compile, err := newCompiler(d)
	if err != nil {
		return err
	}
	view, err := compile(&candidate, nil)
	if err != nil {
		report.Conflicts = append(report.Conflicts, migrate.Item{Source: "candidate", Detail: err.Error()})
		if writeErr := writeJSON(out, report); writeErr != nil {
			return writeErr
		}
		return errors.New("import candidate did not validate")
	}
	view.Upstream.(*forwarder).Close()
	if !*apply {
		return writeJSON(out, report)
	}
	if len(report.Unsupported) != 0 && !*skip {
		if err := writeJSON(out, report); err != nil {
			return err
		}
		return errors.New("review unsupported items before applying; supply compatible data or explicitly accept them")
	}
	initial, err := readState(ctx, d)
	if err != nil {
		return err
	}
	db, err := store.Open(ctx, d.DataDir, initial.Desired)
	if err != nil {
		return err
	}
	defer db.Close()
	publisher, err := runtime.Open(ctx, db, compile)
	if err != nil {
		return err
	}
	defer publisher.Close()
	report.Applied, err = publisher.Update(ctx, *base, func(state *config.State) error {
		if candidate.Imports == nil {
			candidate.Imports = make(map[string]time.Time)
		}
		candidate.Imports[identity] = time.Now().UTC()
		*state = candidate
		return nil
	})
	if err != nil {
		return err
	}
	return writeJSON(out, report)
}
