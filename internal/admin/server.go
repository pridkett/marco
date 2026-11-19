// Package admin provides the embedded Marco management console.
package admin

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/pridkett/marco/internal/auth"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
	"github.com/pridkett/marco/internal/querylog"
)

//go:embed assets/*.html assets/*.css
var assets embed.FS

var views = template.Must(template.New("").Funcs(template.FuncMap{
	"when":   dateTime,
	"age":    age,
	"pretty": pretty,
	"label": func(value any) string {
		s := fmt.Sprint(value)
		if s == "" {
			return "—"
		}
		return s
	},
}).ParseFS(assets, "assets/*.html"))

type Hooks struct {
	Snapshot     func() config.State
	Update       contract.Update
	Status       func() any
	Poll         func() error
	Refresh      func(string) error
	Preview      func(contract.Input) (contract.Selection, contract.Result)
	Select       func(netip.Addr, time.Time) contract.Selection
	Lookup       func(string, uint16) contract.LocalResult
	Published    func(string) bool
	LocalIssues  func() any
	TestUpstream func(context.Context, string) (any, error)
	Revision     func() uint64
	Ready        func() bool
}

type server struct {
	auth    *auth.Manager
	history *querylog.Log
	hooks   Hooks
}

var navigation = []navItem{
	{"Overview", "/"}, {"Devices", "/devices"}, {"Local DNS", "/local-dns"},
	{"Policies", "/policies"}, {"Blocklists", "/blocklists"}, {"Query log", "/query-log"},
	{"Settings", "/settings"},
}

type navItem struct{ Label, URL string }

func New(authentication *auth.Manager, history *querylog.Log, hooks Hooks) http.Handler {
	s := &server{auth: authentication, history: history, hooks: hooks}
	mux := http.NewServeMux()

	for _, path := range []string{"/livez", "/healthz", "/readyz"} {
		mux.HandleFunc("GET "+path, s.health)
	}
	mux.HandleFunc("GET /assets/admin.css", s.secure(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "private, max-age=3600")
		http.ServeFileFS(w, r, assets, "assets/admin.css")
	}))
	mux.HandleFunc("GET /login", s.secure(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.auth.Session(r); ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		message := ""
		if r.URL.Query().Get("error") == "oidc" {
			message = "Sign-in failed."
		}
		s.signin(w, r, http.StatusOK, message)
	}))
	mux.HandleFunc("POST /login", s.secure(s.login))
	mux.HandleFunc("GET "+auth.CallbackPath, s.secure(s.callback))
	mux.HandleFunc("POST /logout", s.protected(s.logout))

	for _, item := range navigation {
		path := item.URL
		pattern := path
		if path == "/" {
			pattern = "/{$}"
		}
		mux.HandleFunc("GET "+pattern, s.protected(func(w http.ResponseWriter, r *http.Request, session auth.Session) {
			s.page(w, r, session, path, http.StatusOK, feedback{})
		}))
	}
	mux.HandleFunc("GET /devices/edit", s.protected(func(w http.ResponseWriter, r *http.Request, session auth.Session) {
		s.page(w, r, session, "/devices/edit", http.StatusOK, feedback{})
	}))
	mux.HandleFunc("GET /settings/export", s.protected(s.export))
	for _, edit := range []struct{ path, page, operation string }{
		{"/devices/edit", "/devices/edit", "edit-device"},
		{"/local-dns", "/local-dns", "edit-local-dns"},
		{"/policies", "/policies", "edit-policies"},
		{"/blocklists", "/blocklists", "edit-blocklists"},
		{"/blocklists/toggle", "/blocklists", "toggle-list"},
		{"/settings/upstreams", "/settings", "edit-upstreams"},
		{"/settings/import", "/settings", "import-settings"},
	} {
		mux.HandleFunc("POST "+edit.path, s.protected(func(w http.ResponseWriter, r *http.Request, session auth.Session) {
			s.edit(w, r, session, edit.page, edit.operation)
		}))
	}
	for _, action := range []struct{ path, page, operation string }{
		{"/devices/poll", "/devices", "poll-controller"},
		{"/blocklists/refresh", "/blocklists", "refresh-list"},
		{"/policies/test", "/policies", "test-policy"},
		{"/blocklists/test", "/blocklists", "test-policy"},
		{"/settings/test-upstream", "/settings", "test-upstream"},
	} {
		mux.HandleFunc("POST "+action.path, s.protected(func(w http.ResponseWriter, r *http.Request, session auth.Session) {
			s.action(w, r, session, action.page, action.operation)
		}))
	}
	return mux
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/readyz" && (s.hooks.Ready == nil || !s.hooks.Ready()) {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, "DNS is starting.")
		return
	}
	fmt.Fprintln(w, "OK")
}

func (s *server) secure(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		// The browser keeps the form Origin meaningful without sending
		// admin page URLs to the identity provider.
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' https:")
		if s.auth == nil || !s.auth.Secure(r) {
			http.Error(w, "Use the configured HTTPS admin URL.", http.StatusBadRequest)
			return
		}
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		next(w, r)
	}
}

type adminHandler func(http.ResponseWriter, *http.Request, auth.Session)

func (s *server) protected(next adminHandler) http.HandlerFunc {
	return s.secure(func(w http.ResponseWriter, r *http.Request) {
		session, ok := s.auth.Session(r)
		if !ok {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			} else {
				s.signin(w, r, http.StatusUnauthorized, "Sign in to continue.")
			}
			return
		}
		next(w, r, session)
	})
}

type signinPage struct {
	CSRF, Error string
	Local, OIDC bool
}

func (s *server) signin(w http.ResponseWriter, r *http.Request, status int, message string) {
	csrf, err := s.auth.LoginToken(w, r)
	if err != nil {
		http.Error(w, "Sign-in is temporarily unavailable.", http.StatusServiceUnavailable)
		return
	}
	render(w, status, "login", signinPage{
		CSRF: csrf, Error: message, Local: s.auth.LocalEnabled(), OIDC: s.auth.OIDCEnabled(),
	})
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r, 8<<10); err != nil {
		s.signin(w, r, http.StatusBadRequest, err.Error())
		return
	}
	username, password, csrf := r.PostForm.Get("username"), r.PostForm.Get("password"), r.PostForm.Get("csrf")
	operation := "local-sign-in"
	account := "anonymous"
	var location string
	var err error
	switch r.PostForm.Get("method") {
	case "oidc":
		operation = "oidc-start"
		location, err = s.auth.StartOIDC(r, csrf)
	case "local":
		err = s.auth.LoginLocal(w, r, username, password, csrf)
		if err == nil {
			location, account = "/", "local:"+username
		}
	default:
		err = auth.ErrCredentials
	}
	s.audit(r, account, operation, outcome(err), s.revision())
	if err == nil {
		http.Redirect(w, r, location, http.StatusSeeOther)
		return
	}
	status, message := http.StatusUnauthorized, "Sign-in failed."
	switch {
	case errors.Is(err, auth.ErrCSRF):
		status, message = http.StatusForbidden, "Reload the sign-in page and try again."
	case errors.Is(err, auth.ErrRateLimit):
		status, message = http.StatusTooManyRequests, "Too many sign-in attempts. Try again in a minute."
		w.Header().Set("Retry-After", "60")
	}
	s.signin(w, r, status, message)
}

func (s *server) callback(w http.ResponseWriter, r *http.Request) {
	account, err := s.auth.FinishOIDC(w, r)
	if err != nil {
		s.audit(r, "anonymous", "oidc-sign-in", outcome(err), s.revision())
		// Discard authorization parameters from the page URL after processing.
		http.Redirect(w, r, "/login?error=oidc", http.StatusSeeOther)
		return
	}
	s.audit(r, account, "oidc-sign-in", "success", s.revision())
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request, session auth.Session) {
	if err := parseForm(w, r, 8<<10); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err := s.auth.Logout(w, r, session, r.PostForm.Get("csrf"))
	s.audit(r, session.Account, "sign-out", outcome(err), s.revision())
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, auth.ErrCSRF) {
			status = http.StatusForbidden
		}
		http.Error(w, "Unable to sign out. Reload the page and try again.", status)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func outcome(err error) string {
	if err == nil {
		return "success"
	}
	if errors.Is(err, auth.ErrCSRF) {
		return "csrf-rejected"
	}
	if errors.Is(err, auth.ErrRateLimit) {
		return "rate-limited"
	}
	return "failed"
}

func (s *server) audit(r *http.Request, account, operation, result string, revision uint64) bool {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), time.Second)
	defer cancel()
	if err := s.auth.Audit(ctx, account, operation, result, revision); err != nil {
		slog.Warn("could not write admin audit record", "operation", operation, "revision", revision)
		return false
	}
	return true
}

func parseForm(w http.ResponseWriter, r *http.Request, limit int64) error {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/x-www-form-urlencoded" {
		return errors.New("A URL-encoded form is required.")
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if err := r.ParseForm(); err != nil {
		return errors.New("The submitted form is invalid or too large.")
	}
	if r.PostForm == nil {
		return errors.New("A URL-encoded form is required.")
	}
	return nil
}

func (s *server) revision() uint64 {
	if s.hooks.Revision != nil {
		return s.hooks.Revision()
	}
	if s.hooks.Snapshot != nil {
		return s.hooks.Snapshot().Revision
	}
	return 0
}

func render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := views.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("could not render admin page", "template", name, "error", err)
	}
}

func dateTime(t time.Time) string {
	if t.IsZero() {
		return "Unknown"
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

func age(t time.Time) string {
	if t.IsZero() {
		return "Unknown"
	}
	duration := max(0, time.Since(t))
	switch {
	case duration < time.Minute:
		return "Less than a minute ago"
	case duration < time.Hour:
		return plural(int(duration.Minutes()), "minute")
	case duration < 24*time.Hour:
		return plural(int(duration.Hours()), "hour")
	default:
		return plural(int(duration.Hours()/24), "day")
	}
}

func plural(n int, unit string) string {
	if n != 1 {
		unit += "s"
	}
	return strconv.Itoa(n) + " " + unit + " ago"
}

func visible(s string) string {
	return strings.TrimSpace(s)
}
