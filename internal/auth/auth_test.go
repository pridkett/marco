package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

type testStore struct{ db *sql.DB }

func (s testStore) DB() *sql.DB { return s.db }

func (s testStore) Write(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func openManager(t *testing.T, settings Settings) *Manager {
	t.Helper()
	db, err := sql.Open("sqlite", t.TempDir()+"/admin.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	m, err := New(t.Context(), testStore{db}, settings)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

const localTestPassword = "lab"

func localSettings(t *testing.T) Settings {
	t.Helper()
	hash, err := HashPassword([]byte(localTestPassword))
	if err != nil {
		t.Fatal(err)
	}
	return Settings{PublicURL: "https://marco.test", Username: "operator", PasswordHash: hash}
}

func browserRequest(method, path string, cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest(method, "https://marco.test"+path, nil)
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	return r
}

func freshLogin(t *testing.T, m *Manager) (string, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	csrf, err := m.LoginToken(w, browserRequest(http.MethodGet, "/login"))
	if err != nil {
		t.Fatal(err)
	}
	return csrf, testCookie(t, w, loginCookie)
}

func testCookie(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == name {
			if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "" {
				t.Fatalf("unsafe %s cookie", name)
			}
			return cookie
		}
	}
	t.Fatalf("missing %s cookie", name)
	return nil
}

func TestLocalRecoveryWithOfflineIssuerAndRotation(t *testing.T) {
	offline := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer offline.Close()
	settings := localSettings(t)
	settings.Issuer, settings.ClientID, settings.AdminGroup = offline.URL, "marco", "admins"
	m := openManager(t, settings)
	m.oidcClient = offline.Client()
	csrf, login := freshLogin(t, m)
	r := browserRequest(http.MethodPost, "/login", login)
	if _, err := m.StartOIDC(r, csrf); !errors.Is(err, ErrCredentials) {
		t.Fatalf("offline issuer: %v", err)
	}
	w := httptest.NewRecorder()
	r.Header.Set("Origin", "https://elsewhere.test")
	if err := m.LoginLocal(w, r, "operator", localTestPassword, csrf); !errors.Is(err, ErrCSRF) {
		t.Fatalf("foreign origin: %v", err)
	}
	r.Header.Set("Origin", "https://marco.test")
	if err := m.LoginLocal(w, r, "operator", localTestPassword, csrf); err != nil {
		t.Fatal(err)
	}
	old := testCookie(t, w, sessionCookie)
	if session, valid := m.Session(browserRequest(http.MethodGet, "/", old)); !valid ||
		session.Account != "local:operator" || session.DisplayName != "local:operator" {
		t.Fatalf("session valid = %v, account = %q, display name = %q", valid, session.Account, session.DisplayName)
	}
	w = httptest.NewRecorder()
	r.AddCookie(old)
	if err := m.LoginLocal(w, r, "operator", localTestPassword, csrf); err != nil {
		t.Fatal(err)
	}
	if _, valid := m.Session(browserRequest(http.MethodGet, "/", old)); valid {
		t.Fatal("rotated session still accepted")
	}
	rotated := testCookie(t, w, sessionCookie)
	logout := browserRequest(http.MethodPost, "/logout", rotated)
	session, valid := m.Session(logout)
	if !valid {
		t.Fatal("new session invalid")
	}
	if err := m.Logout(httptest.NewRecorder(), logout, session, csrf); !errors.Is(err, ErrCSRF) {
		t.Fatalf("anonymous credential used for logout: %v", err)
	}
	if err := m.Logout(httptest.NewRecorder(), logout, session, session.CSRF); err != nil {
		t.Fatal(err)
	}
	if _, valid := m.Session(logout); valid {
		t.Fatal("revoked session still accepted")
	}
}

func TestLoginRateAndTrustedProxy(t *testing.T) {
	settings := localSettings(t)
	settings.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	m := openManager(t, settings)
	csrf, login := freshLogin(t, m)
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/login", nil)
	r.AddCookie(login)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "marco.test")
	r.Header.Set("X-Real-IP", "192.0.2.42")
	if m.Secure(r) || m.ClientIP(r).String() == "192.0.2.42" {
		t.Fatal("untrusted forwarded fields accepted")
	}
	r.RemoteAddr = "127.0.0.1:34111"
	if !m.Secure(r) || m.ClientIP(r).String() != "192.0.2.42" {
		t.Fatal("trusted forwarding not recognized")
	}
	for range 5 {
		if err := m.LoginLocal(httptest.NewRecorder(), r, "somebody", "wrong password", csrf); !errors.Is(err, ErrCredentials) {
			t.Fatalf("invalid password: %v", err)
		}
	}
	if err := m.LoginLocal(httptest.NewRecorder(), r, "operator", localTestPassword, csrf); !errors.Is(err, ErrRateLimit) {
		t.Fatalf("rate limit: %v", err)
	}
}

type exchange struct {
	challenge, userInfoSubject string
	claims                     map[string]any
}

func TestOIDCPKCEStateNonceAndGroup(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	exchanges := make(chan exchange, 1)
	const email = "admin@example.test"
	var issuer string
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
				"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys",
				"userinfo_endpoint":                     issuer + "/userinfo",
				"id_token_signing_alg_values_supported": []string{"RS256"},
				"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
			})
		case "/keys":
			enc := base64.RawURLEncoding
			json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA", "alg": "RS256", "kid": "testing", "use": "sig",
				"n": enc.EncodeToString(key.N.Bytes()), "e": enc.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}})
		case "/token":
			x := <-exchanges
			if err := r.ParseForm(); err != nil || r.Form.Get("code") != "test-code" ||
				r.Form.Get("redirect_uri") != "https://marco.test/auth/callback" {
				w.WriteHeader(http.StatusBadRequest)
				t.Error("invalid exchange form")
				return
			}
			verifier := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(verifier[:]) != x.challenge {
				w.WriteHeader(http.StatusBadRequest)
				t.Error("PKCE verifier did not match")
				return
			}
			token, err := mintToken(key, x.claims)
			if err != nil {
				t.Error(err)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"access_token": "mock-token-" + x.userInfoSubject, "token_type": "Bearer", "id_token": token})
		case "/userinfo":
			var subject string
			switch r.Header.Get("Authorization") {
			case "Bearer mock-token-admin-1":
				subject = "admin-1"
			case "Bearer mock-token-other":
				subject = "other"
			default:
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"sub": subject, "email": email})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer idp.Close()
	issuer = idp.URL
	cases := []struct {
		name, claim                  string
		value                        any
		allowed                      bool
		adminGroup                   string
		userInfoSubject, displayName string
	}{
		{name: "wrong group", claim: "groups", value: []string{"Admin"}},
		{name: "missing group", claim: "groups"},
		{name: "wrong audience", claim: "aud", value: "another-client"},
		{name: "wrong nonce", claim: "nonce", value: "another-login"},
		{name: "default admin group", allowed: true, displayName: email},
		{name: "overridden admin group", claim: "groups", value: []string{"marco-admins"}, allowed: true, adminGroup: "marco-admins", displayName: email},
		{name: "override excludes default group", adminGroup: "marco-admins"},
		{name: "email from userinfo", claim: "email", allowed: true, userInfoSubject: "admin-1", displayName: email},
		{name: "userinfo subject mismatch", claim: "email", allowed: true, userInfoSubject: "other", displayName: "OIDC administrator"},
		{name: "no email available", claim: "email", allowed: true, displayName: "OIDC administrator"},
		{name: "non-string email", claim: "email", value: 42, allowed: true, displayName: "OIDC administrator"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := openManager(t, Settings{PublicURL: "https://marco.test", Issuer: issuer, ClientID: "marco",
				ClientSecret: "fake-test-client-secret", AdminGroup: tc.adminGroup})
			m.oidcClient = idp.Client()
			csrf, login := freshLogin(t, m)
			location, err := m.StartOIDC(browserRequest(http.MethodPost, "/login", login), csrf)
			if err != nil {
				t.Fatal(err)
			}
			authorization, err := url.Parse(location)
			if err != nil {
				t.Fatal(err)
			}
			params := authorization.Query()
			if authorization.Path != "/authorize" || params.Get("code_challenge_method") != "S256" ||
				params.Get("response_type") != "code" || params.Get("state") == "" || params.Get("nonce") == "" ||
				params.Get("scope") != "openid groups email" {
				t.Fatal("authorization request missing protocol fields")
			}
			claims := map[string]any{"iss": issuer, "sub": "admin-1", "aud": "marco", "exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Unix(), "nonce": params.Get("nonce"), "groups": []string{"users", "admin"}, "email": email}
			if tc.claim != "" {
				if tc.value == nil {
					delete(claims, tc.claim)
				} else {
					claims[tc.claim] = tc.value
				}
			}
			exchanges <- exchange{challenge: params.Get("code_challenge"), userInfoSubject: tc.userInfoSubject, claims: claims}
			path := CallbackPath + "?code=test-code&state=" + url.QueryEscape(params.Get("state"))
			if _, err := m.FinishOIDC(httptest.NewRecorder(), browserRequest(http.MethodGet, path)); !errors.Is(err, ErrCredentials) {
				t.Fatalf("unbound browser accepted: %v", err)
			}
			callback := browserRequest(http.MethodGet, path, login)
			w := httptest.NewRecorder()
			account, err := m.FinishOIDC(w, callback)
			if tc.allowed {
				if err != nil || account != issuer+"|admin-1" {
					t.Fatalf("valid ID token failed: %q %v", account, err)
				}
				cookie := testCookie(t, w, sessionCookie)
				if session, valid := m.Session(browserRequest(http.MethodGet, "/", cookie)); !valid ||
					session.Account != account || session.DisplayName != tc.displayName {
					t.Fatalf("session valid = %v, account = %q, display name = %q, want %q", valid, session.Account, session.DisplayName, tc.displayName)
				}
			} else if !errors.Is(err, ErrCredentials) {
				t.Fatalf("invalid ID token accepted: %q %v", account, err)
			}
			if _, err := m.FinishOIDC(httptest.NewRecorder(), callback); !errors.Is(err, ErrCredentials) {
				t.Fatalf("replayed callback: %v", err)
			}
		})
	}
}

func TestUpgradeExistingOIDCSession(t *testing.T) {
	ctx := t.Context()
	db, err := sql.Open("sqlite", t.TempDir()+"/admin.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `CREATE TABLE admin_sessions (
		token TEXT PRIMARY KEY, account TEXT NOT NULL, csrf TEXT NOT NULL,
		scope TEXT NOT NULL, expires INTEGER NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	settings := Settings{PublicURL: "https://marco.test", Issuer: "https://oidc.test", ClientID: "marco", AdminGroup: "admin"}
	const account = "https://oidc.test|admin-1"
	scope := digest(settings.Issuer + "\x00" + settings.ClientID + "\x00" + settings.AdminGroup)
	token, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO admin_sessions VALUES (?, ?, ?, ?, ?)",
		digest(token), account, "existing-csrf", scope, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	r := browserRequest(http.MethodGet, "/", &http.Cookie{Name: sessionCookie, Value: token})
	for range 2 {
		m, err := New(ctx, testStore{db}, settings)
		if err != nil {
			t.Fatal(err)
		}
		if session, valid := m.Session(r); !valid || session.Account != account ||
			session.CSRF != "existing-csrf" || session.DisplayName != "OIDC administrator" {
			t.Fatalf("session valid = %v, account = %q, display name = %q", valid, session.Account, session.DisplayName)
		}
	}
}

func mintToken(key *rsa.PrivateKey, claims map[string]any) (string, error) {
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	b64 := base64.RawURLEncoding
	unsigned := b64.EncodeToString([]byte(`{"alg":"RS256","kid":"testing"}`)) + "." + b64.EncodeToString(body)
	sum := sha256.Sum256([]byte(unsigned))
	signed, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + b64.EncodeToString(signed), nil
}
