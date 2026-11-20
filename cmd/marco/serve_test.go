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
	"path/filepath"
	"testing"
	"time"

	"github.com/pridkett/marco/internal/admin"
	"github.com/pridkett/marco/internal/auth"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/store"
)

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
	authManager, err := auth.New(ctx, db, auth.Settings{PublicURL: settings.PublicURL,
		Issuer: "https://oidc.test", ClientID: "fixture", AdminGroup: "admin"})
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
