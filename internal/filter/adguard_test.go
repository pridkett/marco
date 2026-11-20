package filter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pridkett/marco/internal/config"
)

func TestAdGuardDNSPatterns(t *testing.T) {
	source := config.Subscription{Format: config.AdGuardFormat}
	data := []byte(`! Synthetic registry-pattern coverage
||normal.test^
||ads-*.pattern.test^
@@||ads-allow.pattern.test^
||ads-critical.pattern.test^$important
@@||ads-critical.pattern.test^
||anchor.example
.leading.test^
://at-root.test^
/^tracker[0-9]{2}\.regex\.test$/
||192.0.2.45^
||disabled.test^
||disabled.test^$badfilter
`)
	index, count, err := Parse(data, source)
	if err != nil {
		t.Fatal(err)
	}
	if count != 10 {
		t.Fatalf("got %d usable rules, want 10", count)
	}
	for _, tc := range []struct {
		name         string
		found, allow bool
	}{
		{"sub.normal.test.", true, false},
		{"notnormal.test.", false, false},
		{"sub.ads-2.pattern.test.", true, false},
		{"ads-allow.pattern.test.", true, true},
		{"ads-critical.pattern.test.", true, false},
		{"anchor.example.net.", true, false},
		{"leading.test.", false, false},
		{"sub.leading.test.", true, false},
		{"at-root.test.", true, false},
		{"sub.at-root.test.", false, false},
		{"tracker12.regex.test.", true, false},
		{"tracker123.regex.test.", false, false},
		{"192.0.2.45.", true, false},
		{"disabled.test.", false, false},
	} {
		if got := index.Match(tc.name, true); got.Found != tc.found || got.Allow != tc.allow {
			t.Errorf("%s = %+v", tc.name, got)
		}
	}
	for _, bad := range []string{"||test^$dnsrewrite=192.0.2.2", "||test^$client=guest", "/(?=unsupported)/"} {
		if index, _, err := Parse(append(append([]byte(nil), data...), bad...), source); err == nil || index != nil {
			t.Errorf("accepted unsupported rule %q", bad)
		}
	}
	if _, _, err := Parse(data, config.Subscription{}); err == nil {
		t.Fatal("the plain parser accepted advanced syntax")
	}
}

func TestAdGuardRegistryDownloads(t *testing.T) {
	dir := os.Getenv("MARCO_ADGUARD_TEST_DIR")
	if dir == "" {
		t.Skip("set MARCO_ADGUARD_TEST_DIR to a directory containing downloaded filter_1.txt and filter_2.txt")
	}
	for _, file := range []string{"filter_1.txt", "filter_2.txt"} {
		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, file))
			if err != nil {
				t.Fatal(err)
			}
			index, count, err := Parse(data, config.Subscription{Format: config.AdGuardFormat})
			if err != nil {
				t.Fatal(err)
			}
			if count < 1000 {
				t.Fatalf("unexpected registry rule count %d", count)
			}
			t.Logf("validated %d rules (%d compiled entries)", count, index.Len())
		})
	}
}
