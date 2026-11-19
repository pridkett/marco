package migrate

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Fingerprint identifies an import by file contents and operator dispositions.
func Fingerprint(options Options, allowUnsupported bool) (string, error) {
	h := sha256.New()
	data, err := json.Marshal(struct {
		Disposition Disposition
		Replace     bool
		Skip        bool
	}{options.Disposition, options.ReplaceDesired, allowUnsupported})
	if err != nil {
		return "", err
	}
	h.Write(data)
	for _, path := range []string{options.DesiredPath, options.StatePath, options.ScraperPath, options.PowerDNSPath, options.AdGuardPath} {
		content := sha256.New()
		if path != "" {
			file, err := os.Open(path)
			if err != nil {
				return "", err
			}
			info, err := file.Stat()
			if err != nil || !info.Mode().IsRegular() || info.Size() > 512<<20 {
				file.Close()
				return "", fmt.Errorf("migration input must be a regular file of at most 512 MiB")
			}
			_, err = io.Copy(content, file)
			file.Close()
			if err != nil {
				return "", err
			}
		}
		h.Write(content.Sum(nil))
	}
	if options.PowerDNSPath != "" {
		if info, err := os.Stat(options.PowerDNSPath + "-wal"); err == nil && info.Size() != 0 {
			return "", fmt.Errorf("use a consistent PowerDNS SQLite backup with its WAL checkpointed")
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
