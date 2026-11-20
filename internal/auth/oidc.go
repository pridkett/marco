package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const CallbackPath = "/auth/callback"

type provider struct {
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	userInfo func(context.Context, oauth2.TokenSource) (*oidc.UserInfo, error)
}

var defaultOIDCClient = &http.Client{
	Timeout: 8 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// provider discovers the issuer only when an administrator attempts OIDC sign-in.
func (m *Manager) provider(ctx context.Context) (*provider, error) {
	m.oidcMu.Lock()
	cached := m.oidc
	m.oidcMu.Unlock()
	if cached != nil {
		return cached, nil
	}
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, m.oidcClient), m.cfg.Issuer)
	if err != nil {
		return nil, err
	}
	endpoint := p.Endpoint()
	if _, err := parseHTTPS(endpoint.AuthURL); err != nil {
		return nil, err
	}
	if _, err := parseHTTPS(endpoint.TokenURL); err != nil {
		return nil, err
	}
	// Discovery can name a separate JWKS host. Require TLS there as well.
	var settings struct {
		JWKS string `json:"jwks_uri"`
	}
	if err := p.Claims(&settings); err != nil {
		return nil, err
	}
	if _, err := parseHTTPS(settings.JWKS); err != nil {
		return nil, err
	}
	result := &provider{
		oauth: oauth2.Config{
			ClientID:     m.cfg.ClientID,
			ClientSecret: m.cfg.ClientSecret,
			RedirectURL:  m.origin.String() + CallbackPath,
			Endpoint:     endpoint,
			Scopes:       []string{oidc.ScopeOpenID, "groups", "email"},
		},
		verifier: p.VerifierContext(oidc.ClientContext(context.Background(), m.oidcClient), &oidc.Config{
			ClientID: m.cfg.ClientID,
		}),
	}
	if _, err := parseHTTPS(p.UserInfoEndpoint()); err == nil {
		result.userInfo = p.UserInfo
	}
	m.oidcMu.Lock()
	defer m.oidcMu.Unlock()
	if m.oidc == nil {
		m.oidc = result
	}
	return m.oidc, nil
}

func (m *Manager) StartOIDC(r *http.Request, csrf string) (string, error) {
	if err := m.CheckLoginCSRF(r, csrf); err != nil {
		return "", err
	}
	if !m.OIDCEnabled() {
		return "", ErrCredentials
	}
	if !m.limiter.take("oidc", m.ClientIP(r), time.Now()) {
		return "", ErrRateLimit
	}
	ctx := r.Context()
	p, err := m.provider(ctx)
	if err != nil {
		return "", ErrCredentials
	}
	state, err := randomToken()
	if err != nil {
		return "", err
	}
	nonce, err := randomToken()
	if err != nil {
		return "", err
	}
	verifier, err := randomToken()
	if err != nil {
		return "", err
	}
	now := time.Now()
	err = m.store.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM admin_oidc_attempts WHERE expires <= ?", now.Unix()); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO admin_oidc_attempts(state, browser, verifier, nonce, expires) VALUES (?, ?, ?, ?, ?)
		`, digest(state), digest(csrf), verifier, nonce, now.Add(loginTTL).Unix())
		return err
	})
	if err != nil {
		return "", err
	}
	return p.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)), nil
}

func (m *Manager) FinishOIDC(w http.ResponseWriter, r *http.Request) (string, error) {
	if !m.OIDCEnabled() || !m.Secure(r) || r.Method != http.MethodGet {
		return "", ErrCredentials
	}
	query := r.URL.Query()
	state := query.Get("state")
	browser := cookieToken(r, loginCookie)
	if !validToken(state) || browser == "" {
		return "", ErrCredentials
	}

	ctx := r.Context()
	var verifier, nonce string
	err := m.store.Write(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			DELETE FROM admin_oidc_attempts WHERE state = ? AND browser = ? AND expires > ? RETURNING verifier, nonce
		`, digest(state), digest(browser), time.Now().Unix()).Scan(&verifier, &nonce)
	})
	if err != nil || query.Has("error") || query.Get("code") == "" {
		return "", ErrCredentials
	}
	if issuer := query.Get("iss"); issuer != "" && issuer != m.cfg.Issuer {
		return "", ErrCredentials
	}

	p, err := m.provider(ctx)
	if err != nil {
		return "", ErrCredentials
	}
	ctx = oidc.ClientContext(ctx, m.oidcClient)
	token, err := p.oauth.Exchange(ctx, query.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		return "", ErrCredentials
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return "", ErrCredentials
	}
	idToken, err := p.verifier.Verify(ctx, raw)
	if err != nil || idToken.Subject == "" || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonce)) != 1 {
		return "", ErrCredentials
	}
	var claims struct {
		Groups []string `json:"groups"`
		Email  any      `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil || !slices.Contains(claims.Groups, m.cfg.AdminGroup) {
		return "", ErrCredentials
	}
	email, _ := claims.Email.(string)
	email = strings.TrimSpace(email)
	if email == "" && p.userInfo != nil && token.AccessToken != "" {
		info, err := p.userInfo(ctx, oauth2.StaticTokenSource(token))
		if err == nil && info.Subject == idToken.Subject {
			email = strings.TrimSpace(info.Email)
		}
	}
	account := idToken.Issuer + "|" + idToken.Subject
	if err := m.startSession(w, r, account, m.oidcScope, email); err != nil {
		return "", err
	}
	return account, nil
}
