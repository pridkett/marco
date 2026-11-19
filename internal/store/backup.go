package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

const StateFile = "marco.db"
const HistoryFile = "history.db"

func sqliteCopy(ctx context.Context, source, destination string) error {
	path, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return err
	}
	defer db.Close()
	var check string
	if err := db.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&check); err != nil {
		return err
	}
	if check != "ok" {
		return fmt.Errorf("SQLite integrity check failed for %s", filepath.Base(source))
	}
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", destination); err != nil {
		return err
	}
	if err := os.Chmod(destination, 0600); err != nil {
		return err
	}
	file, err := os.OpenFile(destination, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

// Backup writes a consistent copy to a new directory. The caller holds the instance lock.
func Backup(ctx context.Context, directory, destination string) error {
	output, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		if err != nil {
			return err
		}
		return fmt.Errorf("backup destination already exists")
	}
	stage, err := os.MkdirTemp(filepath.Dir(output), ".marco-backup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := copyFiles(ctx, directory, stage); err != nil {
		return err
	}
	return os.Rename(stage, output)
}

// Restore restores into an empty instance directory. The caller holds the instance lock.
func Restore(ctx context.Context, backup, directory string) error {
	for _, name := range []string{StateFile, HistoryFile} {
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			if _, err := os.Lstat(filepath.Join(directory, name+suffix)); !os.IsNotExist(err) {
				return fmt.Errorf("restore destination contains %s", name+suffix)
			}
		}
	}
	stage, err := os.MkdirTemp(directory, ".marco-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := copyFiles(ctx, backup, stage); err != nil {
		return err
	}
	history := filepath.Join(directory, HistoryFile)
	if err := os.Rename(filepath.Join(stage, HistoryFile), history); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(filepath.Join(stage, StateFile), filepath.Join(directory, StateFile)); err != nil {
		os.Remove(history)
		return err
	}
	return nil
}

func copyFiles(ctx context.Context, directory, destination string) error {
	for _, name := range []string{StateFile, HistoryFile} {
		source := filepath.Join(directory, name)
		info, err := os.Lstat(source)
		if os.IsNotExist(err) && name == HistoryFile {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular database file", name)
		}
		if err := sqliteCopy(ctx, source, filepath.Join(destination, name)); err != nil {
			return fmt.Errorf("copy %s: %w", name, err)
		}
	}
	return nil
}
