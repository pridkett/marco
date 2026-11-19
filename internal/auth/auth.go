// Package auth authenticates Marco administrators and protects browser sessions.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookie = "__Host-marco_session"
	loginCookie   = "__Host-marco_login"
	loginTTL      = 10 * time.Minute
)

var (
	ErrCredentials = errors.New("sign-in failed")
	ErrRateLimit   = errors.New("too many sign-in attempts")
	ErrCSRF        = errors.New("request did not pass the security check")
)

type Store interface {
	DB() *sql.DB
	Write(context.Context, func(*sql.Tx) error) error
}

type Settings struct {
	PublicURL      string
	TrustedProxies []netip.Prefix
	Username       string
	PasswordHash   string
	Issuer         string
	ClientID       string
	ClientSecret   string
	AdminGroup     string
	SessionTTL     time.Duration
}

type Manager struct {
	store      Store
	cfg        Settings
	origin     *url.URL
	salt       []byte
	password   []byte
	localScope string
	oidcScope  string
	limiter    loginLimiter
	kdf        chan struct{}
	oidcMu     sync.Mutex
	oidc       *provider
	oidcClient *http.Client
}

type Session struct {
	Account string
	CSRF    string
}

func New(ctx context.Context, store Store, cfg Settings) (*Manager, error) {
	origin, err := parseHTTPS(cfg.PublicURL)
	if err != nil || (origin.Path != "" && origin.Path != "/") || origin.RawQuery != "" {
		return nil, errors.New("admin public URL must be an HTTPS origin")
	}
	origin.Path = ""
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	for _, p := range cfg.TrustedProxies {
		if !p.IsValid() {
			return nil, errors.New("invalid admin trusted proxy prefix")
		}
	}
	m := &Manager{store: store, cfg: cfg, origin: origin, oidcClient: defaultOIDCClient, kdf: make(chan struct{}, 1)}
	if cfg.Username != "" || cfg.PasswordHash != "" {
		if cfg.Username == "" || len(cfg.Username) > 256 || strings.TrimSpace(cfg.Username) != cfg.Username {
			return nil, errors.New("local admin username is missing or invalid")
		}
		m.salt, m.password, err = parsePassword(cfg.PasswordHash)
		if err != nil {
			return nil, err
		}
		m.localScope = digest(m.cfg.Username + "\x00" + strings.TrimSpace(m.cfg.PasswordHash))
	}
	if cfg.Issuer != "" || cfg.ClientID != "" || cfg.ClientSecret != "" || cfg.AdminGroup != "" {
		if issuer, err := parseHTTPS(cfg.Issuer); err != nil || issuer.RawQuery != "" || cfg.ClientID == "" || cfg.AdminGroup == "" {
			return nil, errors.New("OIDC requires an HTTPS issuer, client ID and admin group")
		}
		m.oidcScope = digest(cfg.Issuer + "\x00" + cfg.ClientID + "\x00" + cfg.AdminGroup)
	}
	if !m.LocalEnabled() && !m.OIDCEnabled() {
		return nil, errors.New("configure an admin sign-in method")
	}
	err = store.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			CREATE TABLE IF NOT EXISTS admin_sessions (
				token TEXT PRIMARY KEY, account TEXT NOT NULL, csrf TEXT NOT NULL,
				scope TEXT NOT NULL, expires INTEGER NOT NULL
			);
			CREATE INDEX IF NOT EXISTS admin_sessions_expiry ON admin_sessions(expires);
			CREATE TABLE IF NOT EXISTS admin_oidc_attempts (
				state TEXT PRIMARY KEY, browser TEXT NOT NULL, verifier TEXT NOT NULL,
				nonce TEXT NOT NULL, expires INTEGER NOT NULL
			);
			CREATE INDEX IF NOT EXISTS admin_oidc_attempts_expiry ON admin_oidc_attempts(expires);
			CREATE TABLE IF NOT EXISTS admin_audit (
				time INTEGER NOT NULL, account TEXT NOT NULL, operation TEXT NOT NULL,
				result TEXT NOT NULL, revision INTEGER NOT NULL
			);
		`)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("initialize admin storage: %w", err)
	}
	return m, nil
}

func parseHTTPS(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.ForceQuery {
		return nil, errors.New("invalid HTTPS URL")
	}
	return u, nil
}

func (m *Manager) LocalEnabled() bool { return m.localScope != "" }
func (m *Manager) OIDCEnabled() bool  { return m.oidcScope != "" }

func (m *Manager) trustedProxy(r *http.Request) bool {
	peer := peerIP(r)
	for _, prefix := range m.cfg.TrustedProxies {
		if prefix.Contains(peer) {
			return true
		}
	}
	return false
}

func peerIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, _ := netip.ParseAddr(host)
	return ip.Unmap()
}

func (m *Manager) ClientIP(r *http.Request) netip.Addr {
	if m.trustedProxy(r) {
		// Accept a single explicitly set address. A proxy must overwrite the
		// header with its socket peer rather than append a client-supplied value.
		addresses := r.Header.Values("X-Real-IP")
		if len(addresses) == 1 {
			if ip, err := netip.ParseAddr(addresses[0]); err == nil && ip.Zone() == "" {
				return ip.Unmap()
			}
		}
	}
	return peerIP(r)
}

func (m *Manager) Secure(r *http.Request) bool {
	host := r.Host
	secure := r.TLS != nil
	if m.trustedProxy(r) {
		proto := r.Header.Values("X-Forwarded-Proto")
		if len(proto) == 1 && proto[0] == "https" {
			secure = true
			forwarded := r.Header.Values("X-Forwarded-Host")
			if len(forwarded) == 1 {
				host = forwarded[0]
			}
		}
	}
	return secure && strings.EqualFold(normalizeHost(host), normalizeHost(m.origin.Host))
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(host, ":443")
}

func (m *Manager) sameOrigin(raw string) bool {
	u, err := parseHTTPS(raw)
	return err == nil && strings.EqualFold(normalizeHost(u.Host), normalizeHost(m.origin.Host))
}

func (m *Manager) CheckCSRF(r *http.Request, expected, supplied string) error {
	if !m.Secure(r) || !validToken(expected) || !validToken(supplied) ||
		subtle.ConstantTimeCompare([]byte(expected), []byte(supplied)) != 1 {
		return ErrCSRF
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return ErrCSRF
	}
	if origins := r.Header.Values("Origin"); len(origins) != 0 {
		if len(origins) != 1 || !m.sameOrigin(origins[0]) {
			return ErrCSRF
		}
	} else if referer := r.Referer(); referer != "" && !m.sameOrigin(referer) {
		return ErrCSRF
	}
	return nil
}

func (m *Manager) LoginToken(w http.ResponseWriter, r *http.Request) (string, error) {
	if token := cookieToken(r, loginCookie); token != "" {
		return token, nil
	}
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	setCookie(w, loginCookie, token, loginTTL)
	return token, nil
}

func (m *Manager) CheckLoginCSRF(r *http.Request, supplied string) error {
	return m.CheckCSRF(r, cookieToken(r, loginCookie), supplied)
}

func (m *Manager) Session(r *http.Request) (Session, bool) {
	token := cookieToken(r, sessionCookie)
	if token == "" {
		return Session{}, false
	}
	var session Session
	var scope string
	err := m.store.DB().QueryRowContext(r.Context(), `
		SELECT account, csrf, scope FROM admin_sessions WHERE token = ? AND expires > ?
	`, digest(token), time.Now().Unix()).Scan(&session.Account, &session.CSRF, &scope)
	return session, err == nil && scope != "" && (scope == m.localScope || scope == m.oidcScope)
}

func (m *Manager) LoginLocal(w http.ResponseWriter, r *http.Request, username, password, csrf string) error {
	if err := m.CheckLoginCSRF(r, csrf); err != nil {
		return err
	}
	if !m.LocalEnabled() || len(password) > maxPassword || len(username) > 256 {
		return ErrCredentials
	}
	if !m.limiter.take("password", m.ClientIP(r), time.Now()) {
		return ErrRateLimit
	}
	select {
	case m.kdf <- struct{}{}:
		defer func() { <-m.kdf }()
	default:
		return ErrRateLimit
	}
	expectedUser := sha256.Sum256([]byte(m.cfg.Username))
	usernameHash := sha256.Sum256([]byte(username))
	sameUser := subtle.ConstantTimeCompare(expectedUser[:], usernameHash[:])
	passwordBytes := []byte(password)
	defer clear(passwordBytes)
	if sameUser&matchPassword(passwordBytes, m.salt, m.password) != 1 {
		return ErrCredentials
	}
	return m.startSession(w, r, "local:"+m.cfg.Username, m.localScope)
}

func (m *Manager) startSession(w http.ResponseWriter, r *http.Request, account, scope string) error {
	token, err := randomToken()
	if err != nil {
		return err
	}
	csrf, err := randomToken()
	if err != nil {
		return err
	}
	now := time.Now()
	ctx := r.Context()
	err = m.store.Write(ctx, func(tx *sql.Tx) error {
		oldToken := digest(cookieToken(r, sessionCookie))
		if _, err := tx.ExecContext(ctx, "DELETE FROM admin_sessions WHERE expires <= ? OR token = ?", now.Unix(), oldToken); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO admin_sessions(token, account, csrf, scope, expires) VALUES (?, ?, ?, ?, ?)",
			digest(token), account, csrf, scope, now.Add(m.cfg.SessionTTL).Unix())
		return err
	})
	if err != nil {
		return err
	}
	setCookie(w, sessionCookie, token, m.cfg.SessionTTL)
	setCookie(w, loginCookie, "", -time.Second)
	return nil
}

func (m *Manager) Logout(w http.ResponseWriter, r *http.Request, session Session, csrf string) error {
	if err := m.CheckCSRF(r, session.CSRF, csrf); err != nil {
		return err
	}
	ctx := r.Context()
	err := m.store.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "DELETE FROM admin_sessions WHERE token = ?", digest(cookieToken(r, sessionCookie)))
		return err
	})
	if err == nil {
		setCookie(w, sessionCookie, "", -time.Second)
	}
	return err
}

func (m *Manager) Audit(ctx context.Context, account, operation, result string, revision uint64) error {
	return m.store.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO admin_audit(time, account, operation, result, revision) VALUES (?, ?, ?, ?, ?)
		`, time.Now().Unix(), account, operation, result, revision)
		return err
	})
}

func setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: int(ttl / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func cookieToken(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil || !validToken(cookie.Value) {
		return ""
	}
	return cookie.Value
}

func randomToken() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func validToken(value string) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(32) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 32
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type attempts struct {
	count int
	until time.Time
}

type loginLimiter struct {
	mu     sync.Mutex
	local  map[string]attempts
	global map[string]attempts
}

func (l *loginLimiter) take(kind string, peer netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.global == nil {
		l.global = make(map[string]attempts)
	}
	global := l.global[kind]
	if !now.Before(global.until) {
		global = attempts{until: now.Add(time.Minute)}
		for key, recent := range l.local {
			if !now.Before(recent.until) {
				delete(l.local, key)
			}
		}
	}
	if global.count >= 30 {
		return false
	}
	if l.local == nil {
		l.local = make(map[string]attempts)
	}
	key := kind + ":" + peer.String()
	bucket := l.local[key]
	if !now.Before(bucket.until) {
		bucket = attempts{until: now.Add(time.Minute)}
	}
	if bucket.count >= 5 {
		return false
	}
	bucket.count++
	global.count++
	l.global[kind] = global
	l.local[key] = bucket
	return true
}
