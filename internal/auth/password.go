package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	passwordMemory = 19 * 1024
	passwordTime   = 2
	passwordLanes  = 1
	passwordSize   = 32
	saltSize       = 16
	maxPassword    = 1024
)

const hashPrefix = "$argon2id$v=19$m=19456,t=2,p=1$"

func HashPassword(password []byte) (string, error) {
	if err := validatePassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return encodePassword(password, salt), nil
}

// HashEnvironmentPassword uses an instance-specific salt so local sessions
// remain valid across restarts with the same credentials.
func HashEnvironmentPassword(ctx context.Context, store Store, password []byte) (string, error) {
	if err := validatePassword(password); err != nil {
		return "", err
	}
	var salt []byte
	err := store.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS admin_password_salt (
			id INTEGER PRIMARY KEY CHECK (id = 1), salt BLOB NOT NULL CHECK (length(salt) = 16)
		)`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO admin_password_salt VALUES (1, randomblob(16))`); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, "SELECT salt FROM admin_password_salt WHERE id = 1").Scan(&salt)
	})
	if err != nil {
		return "", fmt.Errorf("initialize local password salt: %w", err)
	}
	if len(salt) != saltSize {
		return "", errors.New("invalid local password salt")
	}
	return encodePassword(password, salt), nil
}

func validatePassword(password []byte) error {
	if len(password) == 0 {
		return errors.New("password cannot be empty")
	}
	if len(password) > maxPassword {
		return fmt.Errorf("password exceeds %d bytes", maxPassword)
	}
	return nil
}

func encodePassword(password, salt []byte) string {
	digest := argon2.IDKey(password, salt, passwordTime, passwordMemory, passwordLanes, passwordSize)
	defer clear(digest)
	return hashPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(digest)
}

func PromptPassword() (string, error) {
	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("open password prompt: %w", err)
	}
	defer terminal.Close()

	prompt := func(label string) ([]byte, error) {
		fmt.Fprint(terminal, label)
		password, err := term.ReadPassword(int(terminal.Fd()))
		fmt.Fprintln(terminal)
		return password, err
	}
	password, err := prompt("Password: ")
	defer clear(password)
	if err != nil {
		return "", err
	}
	confirmation, err := prompt("Confirm password: ")
	defer clear(confirmation)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(password, confirmation) {
		return "", errors.New("passwords do not match")
	}
	return HashPassword(password)
}

func parsePassword(hash string) (salt, digest []byte, err error) {
	encoded, valid := strings.CutPrefix(strings.TrimSpace(hash), hashPrefix)
	saltText, hashText, split := strings.Cut(encoded, "$")
	salt, saltErr := base64.RawStdEncoding.DecodeString(saltText)
	digest, digestErr := base64.RawStdEncoding.DecodeString(hashText)
	if !valid || !split || saltErr != nil || digestErr != nil || len(salt) != saltSize || len(digest) != passwordSize {
		return nil, nil, errors.New("invalid Marco Argon2id password hash")
	}
	return salt, digest, nil
}

func matchPassword(password, salt, digest []byte) int {
	if len(password) > maxPassword {
		password = nil
	}
	got := argon2.IDKey(password, salt, passwordTime, passwordMemory, passwordLanes, passwordSize)
	defer clear(got)
	return subtle.ConstantTimeCompare(digest, got)
}
