package config

import (
	"maps"
	"os"
	"path/filepath"
	"testing"
)

func TestInitialCatalogs(t *testing.T) {
	initial, err := (Deployment{}).ReadInitial()
	if err != nil {
		t.Fatal(err)
	}
	wantGroups := []string{"infrastructure", "mobile", "iot", "trusted", "other"}
	if len(initial.Groups) != len(wantGroups) {
		t.Fatalf("unexpected group count: %v", initial.Groups)
	}
	for _, name := range wantGroups {
		if g, exists := initial.Groups[name]; !exists || g.Mode != "" || g.Subscriptions != nil {
			t.Errorf("group %s should inherit its policy: %+v", name, g)
		}
	}
	if len(initial.Subscriptions) != 2 || !initial.Subscriptions["adguard-filters-1"].Enabled ||
		initial.Subscriptions["adguard-filters-2"].Enabled {
		t.Fatalf("unexpected starter filter selection: %+v", initial.Subscriptions)
	}

	sample, err := (Deployment{Initial: "../../examples/marco.desired.json"}).ReadInitial()
	if err != nil {
		t.Fatal(err)
	}
	delete(sample.Subscriptions, "demo-local")
	if !maps.Equal(initial.Subscriptions, sample.Subscriptions) {
		t.Fatalf("sample subscriptions drifted: %+v", sample.Subscriptions)
	}
	for _, name := range wantGroups {
		if _, exists := sample.Groups[name]; !exists {
			t.Errorf("sample missing group %s", name)
		}
	}

	path := filepath.Join(t.TempDir(), "portable.json")
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	portable, err := (Deployment{Initial: path}).ReadInitial()
	if err != nil {
		t.Fatal(err)
	}
	if len(portable.Groups) != 0 || len(portable.Subscriptions) != 0 {
		t.Fatalf("portable settings picked up unrequested defaults: %+v", portable)
	}
}
