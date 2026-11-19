// Package store owns the durable resolver state and serialized SQLite writer.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/pridkett/marco/internal/config"
	_ "modernc.org/sqlite"
)

var ErrBusy = errors.New("database write queue is full")
var ErrStale = errors.New("configuration revision is stale")

const schema = 1

type Store struct {
	db      *sql.DB
	pending chan struct{}
	writer  chan struct{}
}

// Open creates or migrates the database. The data directory should be private to the service user.
func Open(ctx context.Context, directory string, initial config.Desired) (*Store, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	path, err := filepath.Abs(filepath.Join(directory, StateFile))
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: path}
	u.RawQuery = "_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)"
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(time.Minute)
	s := &Store{db: db, pending: make(chan struct{}, 32), writer: make(chan struct{}, 1)}
	if err := s.migrate(ctx, initial); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate(ctx context.Context, initial config.Desired) error {
	return s.Write(ctx, func(tx *sql.Tx) error {
		var version int
		if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
			return err
		}
		if version > schema {
			return fmt.Errorf("database schema %d is newer than supported schema %d", version, schema)
		}
		if version == schema {
			return nil
		}
		statements := []string{
			`CREATE TABLE dns_state (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, data BLOB NOT NULL)`,
			`CREATE TABLE list_artifacts (source TEXT PRIMARY KEY, metadata BLOB NOT NULL, body BLOB NOT NULL) WITHOUT ROWID`,
			"PRAGMA user_version=1",
		}
		for _, stmt := range statements {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return err
			}
		}
		state := config.State{Revision: 1, Desired: initial}
		data, err := json.Marshal(state)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO dns_state VALUES(1, 1, ?)", data)
		return err
	})
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Write(ctx context.Context, operation func(*sql.Tx) error) error {
	select {
	case s.pending <- struct{}{}:
	default:
		return ErrBusy
	}
	defer func() { <-s.pending }()
	select {
	case s.writer <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.writer }()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := operation(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func load(ctx context.Context, db interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (config.State, error) {
	var state config.State
	var data []byte
	var revision uint64
	if err := db.QueryRowContext(ctx, "SELECT revision, data FROM dns_state WHERE id=1").Scan(&revision, &data); err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, err
	}
	if state.Revision != revision {
		return state, errors.New("database state and revision disagree")
	}
	rows, err := db.QueryContext(ctx, "SELECT source, metadata, body FROM list_artifacts")
	if err != nil {
		return state, err
	}
	defer rows.Close()
	state.Artifacts = map[string]config.Artifact{}
	for rows.Next() {
		var source string
		var metadata, body []byte
		if err := rows.Scan(&source, &metadata, &body); err != nil {
			return state, err
		}
		var artifact config.Artifact
		if err := json.Unmarshal(metadata, &artifact); err != nil {
			return state, err
		}
		artifact.Body = body
		state.Artifacts[source] = artifact
	}
	return state, rows.Err()
}

func (s *Store) Load(ctx context.Context) (config.State, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return config.State{}, err
	}
	defer tx.Rollback()
	return load(ctx, tx)
}

func (s *Store) Save(ctx context.Context, previous, next config.State) error {
	if next.Revision != previous.Revision+1 {
		return errors.New("invalid revision increment")
	}
	state := next
	state.Artifacts = nil
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return s.Write(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, "UPDATE dns_state SET revision=?, data=? WHERE id=1 AND revision=?", next.Revision, data, previous.Revision)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrStale
		}
		for source := range previous.Artifacts {
			if _, exists := next.Artifacts[source]; !exists {
				if _, err := tx.ExecContext(ctx, "DELETE FROM list_artifacts WHERE source=?", source); err != nil {
					return err
				}
			}
		}
		for source, artifact := range next.Artifacts {
			body := artifact.Body
			artifact.Body = nil
			if old, ok := previous.Artifacts[source]; ok {
				old.Body = nil
				if old.Source == artifact.Source && old.Digest == artifact.Digest &&
					old.ETag == artifact.ETag && old.LastModified == artifact.LastModified &&
					old.FetchedAt.Equal(artifact.FetchedAt) && old.RuleCount == artifact.RuleCount {
					continue
				}
			}
			metadata, err := json.Marshal(artifact)
			if err != nil {
				return err
			}
			if old, ok := previous.Artifacts[source]; ok && old.Digest == artifact.Digest {
				_, err = tx.ExecContext(ctx, "UPDATE list_artifacts SET metadata=? WHERE source=?", metadata, source)
			} else {
				_, err = tx.ExecContext(ctx, `INSERT INTO list_artifacts VALUES(?,?,?)
					ON CONFLICT(source) DO UPDATE SET metadata=excluded.metadata, body=excluded.body`, source, metadata, body)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// Inspect reads a consistent state without creating or migrating an instance.
func Inspect(ctx context.Context, directory string) (config.State, error) {
	path, err := filepath.Abs(filepath.Join(directory, StateFile))
	if err != nil {
		return config.State{}, err
	}
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return config.State{}, err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return config.State{}, err
	}
	defer tx.Rollback()
	return load(ctx, tx)
}
