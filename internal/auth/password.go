package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
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
	if len(password) < 12 || len(password) > maxPassword {
		return "", errors.New("password must be between 12 and 1024 bytes")
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	digest := argon2.IDKey(password, salt, passwordTime, passwordMemory, passwordLanes, passwordSize)
	return hashPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(digest), nil
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
