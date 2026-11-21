package auth

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

var accessAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512, jose.EdDSA,
}

var accessSigningAlgorithms = func() []string {
	algs := make([]string, 0, len(accessAlgorithms))
	for _, alg := range accessAlgorithms {
		algs = append(algs, string(alg))
	}
	return algs
}()

type AccessToken struct {
	Account string
	Scopes  []string
}

func (m *Manager) PublicOrigin() string { return m.origin.String() }
func (m *Manager) OIDCIssuer() string   { return m.cfg.Issuer }

// AccessOriginAllowed restricts browser requests while allowing native OAuth clients.
func (m *Manager) AccessOriginAllowed(r *http.Request) bool {
	origins := r.Header.Values("Origin")
	if len(origins) == 0 {
		return true
	}
	if len(origins) != 1 {
		return false
	}
	u, err := parseHTTPS(origins[0])
	return err == nil && u.Path == "" && u.RawQuery == "" && m.sameOrigin(origins[0])
}

// VerifyAccessToken verifies a signed JWT access token scoped to the API resource.
func (m *Manager) VerifyAccessToken(ctx context.Context, raw, resource string) (AccessToken, error) {
	if !m.OIDCEnabled() || len(raw) > 16<<10 {
		return AccessToken{}, ErrCredentials
	}
	jws, err := jose.ParseSignedCompact(raw, accessAlgorithms)
	if err != nil {
		return AccessToken{}, ErrCredentials
	}
	typ, _ := jws.Signatures[0].Protected.ExtraHeaders["typ"].(string)
	if !strings.EqualFold(typ, "at+jwt") && !strings.EqualFold(typ, "application/at+jwt") {
		return AccessToken{}, ErrCredentials
	}

	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	p, err := m.provider(ctx)
	if err != nil {
		return AccessToken{}, err
	}
	token, err := p.accessVerifier.Verify(ctx, raw)
	if err != nil || token.Issuer != m.cfg.Issuer || token.Subject == "" ||
		len(token.Subject) > 512 || !token.Expiry.After(time.Now()) ||
		!slices.Contains(token.Audience, resource) ||
		!(len(token.Audience) == 1 || len(token.Audience) == 2 && slices.Contains(token.Audience, m.cfg.Issuer)) {
		return AccessToken{}, ErrCredentials
	}
	var claims struct {
		Scope string `json:"scope"`
	}
	if err := token.Claims(&claims); err != nil {
		return AccessToken{}, ErrCredentials
	}
	return AccessToken{Account: token.Issuer + "|" + token.Subject, Scopes: strings.Fields(claims.Scope)}, nil
}
