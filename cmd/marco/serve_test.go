package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/pridkett/marco/internal/admin"
	"github.com/pridkett/marco/internal/auth"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/store"
)

func TestAdminEnvironmentCredentials(t *testing.T) {
	t.Setenv(config.AdminPasswordEnv, "demo")
	t.Setenv(config.AdminUsernameEnv, "env-admin")
	ctx := t.Context()
	dir := t.TempDir()
	db, err := store.Open(ctx, dir, config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	settings := config.AdminSettings{
		PublicURL: "https://admin.test", Username: "configured-admin",
		PasswordHash: config.SecretRef{File: filepath.Join(dir, "missing.hash")},
	}
	manager, err := openAuth(ctx, db, settings)
	if err != nil {
		t.Fatal(err)
	}
	request := localSessionRequest(t, manager, settings.PublicURL, "env-admin", "demo")
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(ctx, dir, config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	manager, err = openAuth(ctx, reopened, settings)
	if err != nil {
		t.Fatal(err)
	}
	if session, valid := manager.Session(request); !valid || session.Account != "local:env-admin" {
		t.Fatalf("environment-backed session lost after restart: %+v", session)
	}
	t.Setenv(config.AdminPasswordEnv, "new-password")
	manager, err = openAuth(ctx, reopened, settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, valid := manager.Session(request); valid {
		t.Fatal("session survived a password change")
	}
}

func TestAdminProvisionedPasswordRepresentations(t *testing.T) {
	db, err := store.Open(t.Context(), t.TempDir(), config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	hash, err := auth.HashPassword([]byte("demo"))
	if err != nil {
		t.Fatal(err)
	}
	settings := config.AdminSettings{PublicURL: "https://marco.test"}
	t.Setenv(config.AdminUsernameEnv, "")
	t.Setenv(config.AdminPasswordEnv, hash)
	manager, err := openAuth(t.Context(), db, settings)
	if err != nil {
		t.Fatal(err)
	}
	if request := localSessionRequest(t, manager, settings.PublicURL, "admin", "demo"); request.Header.Get("Cookie") == "" {
		t.Fatal("hash-backed login produced no session cookie")
	}

	t.Setenv(config.AdminPasswordEnv, "")
	settings.Password = config.SecretRef{Env: "MARCO_TEST_PASSWORD"}
	for _, value := range []string{"demo", hash} {
		t.Setenv(settings.Password.Env, value)
		manager, err := openAuth(t.Context(), db, settings)
		if err != nil {
			t.Fatal(err)
		}
		localSessionRequest(t, manager, settings.PublicURL, "admin", "demo")
	}

	t.Setenv(settings.Password.Env, "$argon2id$invalid")
	if manager, err := openAuth(t.Context(), db, settings); manager != nil || err == nil {
		t.Fatal("malformed Argon2id string was used as a literal password")
	}
}

func localSessionRequest(t *testing.T, manager *auth.Manager, origin, username, password string) *http.Request {
	t.Helper()
	login := httptest.NewRecorder()
	csrf, err := manager.LoginToken(login, httptest.NewRequest(http.MethodGet, origin+"/login", nil))
	if err != nil {
		t.Fatal(err)
	}
	post := httptest.NewRequest(http.MethodPost, origin+"/login", nil)
	for _, cookie := range login.Result().Cookies() {
		post.AddCookie(cookie)
	}
	signedIn := httptest.NewRecorder()
	if err := manager.LoginLocal(signedIn, post, username, password, csrf); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, origin, nil)
	for _, cookie := range signedIn.Result().Cookies() {
		if cookie.MaxAge > 0 {
			request.AddCookie(cookie)
		}
	}
	return request
}

func TestUniFiLocalAccountPasswordFromEnvironment(t *testing.T) {
	const name = "UNIFI_PASSWORD"
	t.Setenv(name, "")
	settings := config.UniFiSettings{
		Controller: "home", URL: "https://unifi.test", Site: "default", Mode: "local-account",
		Username: "test-reader", Password: config.SecretRef{Env: name},
	}
	if _, err := newUniFi(settings, nil); err == nil {
		t.Fatal("accepted a missing UniFi password")
	}
	t.Setenv(name, "fixture")
	if worker, err := newUniFi(settings, nil); err != nil || worker == nil {
		t.Fatalf("could not set up UniFi polling with an environment password: %v", err)
	}
}

func TestAdminTLSWithWildcardCertificate(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	const hostname = "marco.wagstrom.net"
	settings := config.AdminSettings{Listen: "127.0.0.1:0", PublicURL: "https://" + hostname,
		CertFile: filepath.Join(dir, "fullchain.pem"), KeyFile: filepath.Join(dir, "privkey.pem")}
	roots := writeWildcardCertificate(t, settings)
	db, err := store.Open(ctx, dir, config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	t.Setenv(config.AdminPasswordEnv, "")
	t.Setenv("MARCO_OIDC_CLIENT_SECRET", "test-client-secret")
	settings.Issuer, settings.ClientID = "https://oidc.test", "fixture"
	settings.ClientSecret = config.SecretRef{Env: "MARCO_OIDC_CLIENT_SECRET"}
	authManager, err := openAuth(ctx, db, settings)
	if err != nil {
		t.Fatal(err)
	}
	server, err := startAdmin(ctx, settings, admin.New(authManager, nil, admin.Hooks{}))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Addr)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, settings.PublicURL+"/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.TLS == nil || len(resp.TLS.VerifiedChains) != 1 {
		t.Fatalf("admin wildcard HTTPS failed: %s", resp.Status)
	}
}

func writeWildcardCertificate(t *testing.T, settings config.AdminSettings) *x509.CertPool {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		DNSNames: []string{"*.wagstrom.net"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	writeTestFile(t, settings.CertFile, string(cert))
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, settings.KeyFile, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})))
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		t.Fatal("could not load fixture root")
	}
	return roots
}
