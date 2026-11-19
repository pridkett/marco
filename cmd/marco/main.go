package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/pridkett/marco/internal/auth"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/migrate"
	"github.com/pridkett/marco/internal/store"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := command(ctx, os.Args[1:], os.Stdout); err != nil && !errors.Is(err, flag.ErrHelp) {
		slog.Error("marco", "error", err)
		os.Exit(1)
	}
}

func usage(out io.Writer) {
	fmt.Fprintln(out, "Usage: marco <command> [options]")
	fmt.Fprintln(out, "Commands: run, validate, export, migrate, backup, restore, password, upstream-test, version")
	fmt.Fprintln(out, "Run 'marco <command> --help' for command options.")
}

func command(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		usage(out)
		return errors.New("a command is required")
	}
	switch args[0] {
	case "help", "--help", "-h":
		usage(out)
		return nil
	case "version", "--version":
		fmt.Fprintln(out, version)
		return nil
	case "password":
		return passwordCommand(args[1:], out)
	case "migrate":
		return migrateCommand(ctx, args[1:], out)
	case "run", "validate", "export", "backup", "restore", "upstream-test":
	default:
		usage(out)
		return fmt.Errorf("unknown command %q", args[0])
	}
	action := args[0]
	flags, file := deploymentFlags(action)
	var output, backup, target string
	var inventory bool
	switch action {
	case "export":
		flags.BoolVar(&inventory, "inventory", false, "export device state separately from settings")
	case "backup":
		flags.StringVar(&output, "output", "", "new destination directory for SQLite snapshots")
	case "restore":
		flags.StringVar(&backup, "backup", "", "directory containing backed-up SQLite databases")
	case "upstream-test":
		flags.StringVar(&target, "pool", "", "pool name or pool:zero-based-endpoint (requires network access)")
	}
	d, err := loadDeployment(flags, file, args[1:])
	if err != nil {
		return err
	}
	switch action {
	case "run":
		return serve(ctx, d)
	case "backup", "restore":
		return backupCommand(ctx, d, action, output, backup)
	}
	state, err := readState(ctx, d)
	if err != nil {
		return err
	}
	if action == "export" {
		if inventory {
			return writeJSON(out, migrate.InventoryState{Version: config.Version, Devices: state.Devices, SitePolls: state.SitePolls})
		}
		return writeJSON(out, state.Desired)
	}
	compile, err := newCompiler(d)
	if err != nil {
		return err
	}
	view, err := compile(&state, nil)
	if err != nil {
		return err
	}
	upstream := view.Upstream.(*forwarder)
	defer upstream.Close()
	if action == "validate" {
		fmt.Fprintf(out, "Configuration is valid at revision %d.\n", state.Revision)
		return nil
	}
	if target == "" {
		target = state.Desired.Default.Pool
		if target == "" {
			for name := range state.Desired.Pools {
				target = name
				break
			}
		}
	}
	status, err := testPool(ctx, upstream, target)
	if status != nil {
		if writeErr := writeJSON(out, status); writeErr != nil {
			return writeErr
		}
	}
	return err
}

func deploymentFlags(name string) (*flag.FlagSet, *string) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	return flags, flags.String("config", "marco.json", "deployment JSON file")
}

func loadDeployment(flags *flag.FlagSet, file *string, args []string) (config.Deployment, error) {
	if err := flags.Parse(args); err != nil {
		return config.Deployment{}, err
	}
	if flags.NArg() != 0 {
		return config.Deployment{}, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	return config.ReadDeployment(*file)
}

func readState(ctx context.Context, d config.Deployment) (config.State, error) {
	if _, err := os.Lstat(filepath.Join(d.DataDir, store.StateFile)); errors.Is(err, os.ErrNotExist) {
		initial, err := d.ReadInitial()
		return config.State{Revision: 1, Desired: initial}, err
	} else if err != nil {
		return config.State{}, err
	}
	return store.Inspect(ctx, d.DataDir)
}

func writeJSON(out io.Writer, v any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}

func backupCommand(ctx context.Context, d config.Deployment, action, output, backup string) error {
	if action == "backup" && output == "" || action == "restore" && backup == "" {
		return errors.New("backup requires --output and restore requires --backup")
	}
	lock, err := store.Lock(d.DataDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	if action == "restore" {
		return store.Restore(ctx, backup, d.DataDir)
	}
	return store.Backup(ctx, d.DataDir, output)
}

func passwordCommand(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("password", flag.ContinueOnError)
	path := flags.String("out", "", "write or replace the hash file with permissions 0600")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("password accepts no positional arguments")
	}
	hash, err := auth.PromptPassword()
	if err != nil {
		return err
	}
	if *path == "" {
		_, err := fmt.Fprintln(out, hash)
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(*path), ".marco-password-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, err = fmt.Fprintln(file, hash)
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(file.Name(), *path)
}
