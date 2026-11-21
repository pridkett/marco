package config

import (
	"maps"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalAdminDefaultsAndEnvironment(t *testing.T) {
	t.Setenv(AdminUsernameEnv, "")
	t.Setenv(AdminPasswordEnv, "")
	d, err := ReadDeployment("../../examples/marco.json")
	if err != nil {
		t.Fatal(err)
	}
	if d.Admin.LocalUsername() != "admin" {
		t.Fatalf("unexpected sample username %q", d.Admin.LocalUsername())
	}
	if d.Admin.Password.Env != AdminPasswordEnv {
		t.Fatalf("unexpected sample credential source: %+v", d.Admin.Password)
	}
	d.Admin.Username, d.Admin.Password, d.Admin.PasswordHash = "", SecretRef{}, SecretRef{}
	if err := d.Validate(); err == nil {
		t.Fatal("accepted an admin listener with no authentication configured")
	}
	t.Setenv(AdminPasswordEnv, "demo")
	if err := d.Validate(); err != nil {
		t.Fatalf("environment-only login: %v", err)
	}
	if d.Admin.LocalUsername() != "admin" {
		t.Fatalf("unexpected fallback username %q", d.Admin.LocalUsername())
	}
}

func TestOIDCOnlyDeployment(t *testing.T) {
	t.Setenv(AdminPasswordEnv, "")
	d, err := ReadDeployment("../../examples/marco.json")
	if err != nil {
		t.Fatal(err)
	}
	d.Admin.Password = SecretRef{}
	d.Admin.ManagementAPI = true
	if err := d.Validate(); err == nil {
		t.Fatal("accepted the management API without OIDC")
	}
	d.Admin.Issuer = "https://issuer.test"
	d.Admin.ClientID = "marco"
	d.Admin.ClientSecret = SecretRef{Env: "MARCO_OIDC_CLIENT_SECRET"}
	if err := d.Validate(); err != nil {
		t.Fatalf("OIDC-only deployment with management API: %v", err)
	}
	for _, limit := range []int{-1, MaxManagementPageSize + 1} {
		d.Admin.ManagementMaxPageSize = limit
		if err := d.Validate(); err == nil {
			t.Fatalf("accepted management page size %d outside the supported range", limit)
		}
	}
	d.Admin.ManagementMaxPageSize = 1000
	if err := d.Validate(); err != nil {
		t.Fatalf("management page size of 1000: %v", err)
	}
	d.Admin.Listen = ""
	if err := d.Validate(); err == nil {
		t.Fatal("accepted the management API without an admin listener")
	}
}

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
