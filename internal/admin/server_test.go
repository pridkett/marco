package admin

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/auth"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
	"github.com/pridkett/marco/internal/filter"
	"github.com/pridkett/marco/internal/querylog"
)

type testDB struct{ db *sql.DB }

func TestHeaderDisplaysAccountEmail(t *testing.T) {
	s := &server{}
	r := httptest.NewRequest(http.MethodGet, "https://marco.test/policies", nil)
	w := httptest.NewRecorder()
	session := auth.Session{Account: "https://oidc.test|admin-1", DisplayName: "admin&ops@example.test"}
	s.page(w, r, session, r.URL.Path, http.StatusOK, feedback{})
	body := w.Body.String()
	if w.Code != http.StatusOK || strings.Contains(body, session.Account) ||
		!strings.Contains(body, `<span class="account-name" title="admin&amp;ops@example.test">admin&amp;ops@example.test</span>`) {
		t.Fatalf("unexpected account header in HTTP %d response", w.Code)
	}
}

func TestUnavailableAuthenticationReturnsServiceUnavailable(t *testing.T) {
	handler := New(nil, nil, Hooks{Ready: func() bool { return true }})
	for _, path := range []string{"/", "/login"} {
		response := request(handler, http.MethodGet, path, nil)
		if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "Admin sign-in is unavailable") {
			t.Fatalf("%s returned HTTP %d with %q", path, response.Code, response.Body.String())
		}
	}
	if response := request(handler, http.MethodGet, "/readyz", nil); response.Code != http.StatusOK {
		t.Fatalf("DNS readiness returned HTTP %d", response.Code)
	}
}

func (s testDB) DB() *sql.DB { return s.db }
func (s testDB) Write(ctx context.Context, fn func(*sql.Tx) error) error {
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

type fixture struct {
	handler  http.Handler
	db       *sql.DB
	state    config.State
	cookie   *http.Cookie
	csrf     string
	triggers int
}

func setup(t *testing.T) *fixture {
	t.Helper()
	return setupWithHooks(t, nil)
}

func setupWithHooks(t *testing.T, configure func(*Hooks)) *fixture {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "admin.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	password, err := auth.HashPassword([]byte("local recovery password"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := auth.New(t.Context(), testDB{db}, auth.Settings{
		PublicURL: "https://marco.test", Username: "operator", PasswordHash: password,
	})
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "history.sqlite")
	history, err := querylog.Open(logPath, querylog.Settings{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	midnight := now.UTC().Truncate(24 * time.Hour)
	history.Observe(contract.Event{
		Input: contract.Input{
			Time: midnight.Add(-time.Second), Name: "blocked.test.", Type: dns.TypeA, Peer: netip.MustParseAddr("192.0.2.2"),
		},
		Result: contract.Result{Origin: "policy", RCode: dns.RcodeNameError, Reason: "subscription-block", Rule: "test"},
		Node:   "fixture", Latency: time.Millisecond,
	})
	history.Observe(contract.Event{
		Input: contract.Input{
			Time: midnight, Name: "js.monitor.azure.com.", Type: dns.TypeHTTPS, Peer: netip.MustParseAddr("2001:db8::2"),
		},
		Result: contract.Result{Origin: "upstream", RCode: dns.RcodeSuccess, Reason: "upstream-answer", Cache: "miss",
			Rule: "adguard-filters-1/@@||js.monitor.azure.com^|"},
		Node: "fixture", Latency: 123 * time.Microsecond,
	})
	if err := history.Close(); err != nil {
		t.Fatal(err)
	}
	history, err = querylog.Open(logPath, querylog.Settings{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { history.Close() })
	desired := config.Defaults()
	desired.Groups = map[string]config.Policy{"IoT": {Mode: config.LocalOnly}}
	desired.Pools = map[string][]config.Endpoint{"primary": {{Transport: "dot", ServerName: "resolver.test", Address: "192.0.2.71"}}}
	desired.Zones = []config.Zone{{Name: "home.arpa.", Private: true, Publish: true}}
	desired.Records = []config.Record{{Name: "console.home.arpa.", Type: "CNAME", Value: "no-owner.home.arpa."}}
	desired.Devices = map[string]config.DeviceSettings{"cam-01": {Group: "IoT"}}
	desired.Subscriptions = map[string]config.Subscription{
		"fixture": {Enabled: true, URL: "https://filter.test/domains.txt"},
		"staging": {Enabled: true, URL: "https://filter.test/staging.txt"},
	}
	fixture := &fixture{db: db, state: config.State{
		Revision: 4, Desired: desired,
		Devices: map[string]config.Device{"cam-01": {
			ID: "cam-01", Canonical: "porch-camera", Reported: "Camera <L1>", Controller: "test controller", Site: "site",
			Connected: true, LastSeen: now.Add(-time.Minute), LastPoll: now.Add(-time.Minute), Network: "Cameras",
			Addresses: []config.Address{
				{IP: netip.MustParseAddr("192.0.2.32"), Active: true, Publish: true},
				{IP: netip.MustParseAddr("2001:db8::30"), Conflicted: true},
			},
		}},
		SitePolls: map[string]time.Time{"site": now.Add(-time.Minute)},
		Artifacts: map[string]config.Artifact{
			"fixture": {Source: desired.Subscriptions["fixture"], Digest: "fixture-digest", RuleCount: 100, FetchedAt: now},
		},
	}}
	selection := contract.Selection{Group: "IoT", Device: "cam-01", Confidence: "confirmed", Precedence: "device", Seen: now, Policy: desired.Groups["IoT"]}
	hooks := Hooks{
		Snapshot: func() config.State { return fixture.state },
		Revision: func() uint64 { return fixture.state.Revision },
		Ready:    func() bool { return true },
		Status:   func() any { return map[string]any{"memory": 0, "upstream": "ready"} },
		Poll: func() error {
			fixture.triggers++
			return nil
		},
		Refresh: func(id string) error {
			if id != "fixture" {
				return fmt.Errorf("unknown list")
			}
			fixture.triggers++
			return nil
		},
		Lookup: func(name string, qtype uint16) contract.LocalResult {
			if name == "2.2.0.192.in-addr.arpa." && qtype == dns.TypePTR {
				return contract.LocalResult{Found: true, Answer: []dns.RR{&dns.PTR{Ptr: "laptop.home.arpa."}}}
			}
			return contract.LocalResult{Found: true}
		},
		Published:   func(id string) bool { return id == "cam-01" },
		LocalIssues: func() any { return []string{"test-collision"} },
		Preview: func(in contract.Input) (contract.Selection, contract.Result) {
			return selection, contract.Result{Origin: "policy", RCode: dns.RcodeRefused, Reason: "local-only", Rule: "test-rule"}
		},
		Select: func(netip.Addr, time.Time) contract.Selection { return selection },
		TestUpstream: func(_ context.Context, pool string) (any, error) {
			return map[string]any{"status": "reachable", "pool": pool}, nil
		},
		Update: func(_ context.Context, base uint64, change func(*config.State) error) (uint64, error) {
			if base != fixture.state.Revision {
				return fixture.state.Revision, fmt.Errorf("stale edit")
			}
			if err := change(&fixture.state); err != nil {
				return fixture.state.Revision, err
			}
			fixture.state.Revision++
			return fixture.state.Revision, nil
		},
	}
	if configure != nil {
		configure(&hooks)
	}
	fixture.handler = New(manager, history, hooks)
	return fixture
}

var csrfPattern = regexp.MustCompile(`name="csrf" value="([A-Za-z0-9_-]{43})"`)

func request(h http.Handler, method, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://marco.test"+path, strings.NewReader(form.Encode()))
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://marco.test")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func (f *fixture) login(t *testing.T) {
	t.Helper()
	login := request(f.handler, "GET", "/login", nil)
	match := csrfPattern.FindStringSubmatch(login.Body.String())
	if login.Code != http.StatusOK || len(match) != 2 {
		t.Fatalf("missing login page: %d, %s", login.Code, login.Body.String())
	}
	result := request(f.handler, "POST", "/login", url.Values{
		"csrf": {match[1]}, "method": {"local"}, "username": {"operator"}, "password": {"local recovery password"},
	}, login.Result().Cookies()[0])
	if result.Code != http.StatusSeeOther {
		t.Fatalf("sign-in failed: %d %s", result.Code, result.Body.String())
	}
	f.cookie = result.Result().Cookies()[0]
	main := request(f.handler, "GET", "/", nil, f.cookie)
	match = csrfPattern.FindStringSubmatch(main.Body.String())
	if main.Code != http.StatusOK || len(match) != 2 {
		t.Fatalf("missing authenticated session: %d %s", main.Code, main.Body.String())
	}
	f.csrf = match[1]
}

func checkContent(t *testing.T, w *httptest.ResponseRecorder, want ...string) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	for _, needle := range append(want, "</html>") {
		if !strings.Contains(w.Body.String(), needle) {
			t.Errorf("response missing %q", needle)
		}
	}
}

func TestRoutesReadyAuthAndRenderedViews(t *testing.T) {
	f := setup(t)
	unauthenticated := request(f.handler, "GET", "/settings/export", nil)
	if unauthenticated.Code != http.StatusSeeOther || unauthenticated.Header().Get("Location") != "/login" {
		t.Fatal("settings export is reachable without sign-in")
	}
	plain := httptest.NewRequest("GET", "http://marco.test/login", nil)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, plain)
	if w.Code != http.StatusBadRequest || len(w.Result().Cookies()) != 0 {
		t.Fatal("plaintext admin request accepted")
	}
	ready := request(f.handler, "GET", "/readyz", nil)
	if ready.Code != http.StatusOK || ready.Body.String() != "OK\n" {
		t.Fatal("readiness should be usable before sign-in")
	}

	f.login(t)
	cases := []struct {
		path string
		want []string
	}{
		{"/", []string{"Recent activity", "Integration health", "Revision 4"}},
		{"/devices?search=Cameras", []string{"porch-camera", "Camera &lt;L1&gt;", "Ownership conflict", "test-collision", "Assigned to IoT", "Published"}},
		{"/devices/edit?id=cam-01", []string{"Save device", "cam-01"}},
		{"/local-dns", []string{"console.home.arpa.", "Unresolved", "Private", "test-collision"}},
		{"/policies", []string{"Client groups", "Test a DNS decision", "local-only"}},
		{"/blocklists", []string{"fixture-digest", "Waiting for valid list", "Refresh fixture", "/blocklists/test"}},
		{"/query-log?question=BLOCKED&outcome=NXDOMAIN", []string{"<h1>Query Log</h1>", "blocked.test.", `class="query-badge blocked">Blocked`, "NXDOMAIN", "subscription-block", "192.0.2.2"}},
		{"/settings", []string{"Test encrypted endpoints", "Import and export", "Instance status"}},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			resp := request(f.handler, "GET", tc.path, nil, f.cookie)
			checkContent(t, resp, tc.want...)
			if resp.Header().Get("Cache-Control") != "no-store" || resp.Header().Get("Referrer-Policy") != "same-origin" || !strings.Contains(resp.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
				t.Fatal("page missing security headers")
			}
		})
	}
	probe := request(f.handler, "POST", "/policies/test", url.Values{
		"csrf": {f.csrf}, "client": {"192.0.2.32"}, "question": {"blocked.test"}, "type": {"AAAA"},
	}, f.cookie)
	checkContent(t, probe, "test-rule", "REFUSED", "confirmed")
	testUpstream := request(f.handler, "POST", "/settings/test-upstream", url.Values{"csrf": {f.csrf}, "pool": {"primary"}}, f.cookie)
	checkContent(t, testUpstream, "Upstream test completed", "reachable")
}

func TestDashboardBlockingControls(t *testing.T) {
	var pause contract.BlockingPause
	f := setupWithHooks(t, func(h *Hooks) {
		h.Blocking = func(now time.Time) contract.BlockingPause { return pause.At(now) }
		h.SetBlocking = func(_ context.Context, account string, next contract.BlockingPause) error {
			if account != "local:operator" {
				t.Fatalf("unexpected actor %q", account)
			}
			pause = next
			return nil
		}
	})
	if w := request(f.handler, http.MethodGet, "/blocking", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("unauthenticated blocking status returned %d", w.Code)
	}
	f.login(t)
	checkContent(t, request(f.handler, http.MethodGet, "/", nil, f.cookie),
		"Blocking active", "Pause blocking", "Top clients", "Top queried domains", "Top blocked domains", "Indefinite")

	change := func(token, duration string, status int) *httptest.ResponseRecorder {
		t.Helper()
		w := request(f.handler, http.MethodPost, "/blocking?range=1+hour", url.Values{
			"csrf": {token}, "duration": {duration},
		}, f.cookie)
		if w.Code != status {
			t.Fatalf("duration %q returned %d, want %d", duration, w.Code, status)
		}
		return w
	}
	change("", "1m", http.StatusForbidden)
	change(f.csrf, "2m", http.StatusBadRequest)
	if pause.Paused {
		t.Fatal("rejected form changed the pause")
	}
	before := time.Now()
	w := change(f.csrf, "1m", http.StatusSeeOther)
	if !pause.Paused || pause.Until.Before(before.Add(time.Minute)) || pause.Until.After(time.Now().Add(time.Minute)) ||
		w.Header().Get("Location") != "/?range=1+hour" {
		t.Fatalf("unexpected timed pause %+v, redirect %q", pause, w.Header().Get("Location"))
	}
	w = request(f.handler, http.MethodGet, "/blocking", nil, f.cookie)
	var status blockingStatus
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil || w.Code != http.StatusOK || !status.Paused ||
		!status.Until.Equal(pause.Until) || status.RemainingSeconds <= 0 || status.RemainingSeconds > 60 {
		t.Fatalf("unexpected status HTTP %d: %s", w.Code, w.Body)
	}
	checkContent(t, request(f.handler, http.MethodGet, "/?range=1+hour", nil, f.cookie),
		"Blocking paused", "Resumes at", "Resume blocking")
	change(f.csrf, "indefinite", http.StatusSeeOther)
	if !pause.Paused || !pause.Until.IsZero() {
		t.Fatalf("unexpected indefinite pause %+v", pause)
	}
	change(f.csrf, "resume", http.StatusSeeOther)
	if pause.Paused {
		t.Fatal("resume did not restore blocking")
	}
}

func TestDevicesSortAndDisplay(t *testing.T) {
	f := setup(t)
	cam := f.state.Devices["cam-01"]
	cam.Canonical, cam.UniFiFingerprint = "lab-camera", 4488
	f.state.Devices[cam.ID] = cam
	f.state.Devices["desk"] = config.Device{
		ID: "desk", Canonical: "lab-desk", Reported: "lab-desk", Controller: cam.Controller,
		Connected: true, LastSeen: cam.LastSeen.Add(-time.Hour), LastPoll: cam.LastPoll,
		Addresses: []config.Address{{IP: netip.MustParseAddr("192.0.2.7"), Publish: true}},
	}
	f.state.Devices["old"] = config.Device{
		ID: "old", Canonical: "lab-old", Controller: cam.Controller,
		LastConnected: time.Now().Add(-2 * time.Hour), LastPoll: cam.LastPoll,
	}
	f.login(t)

	page := request(f.handler, "GET", "/devices?search=lab&presence=Connected+at+last+poll&sort=addresses", nil, f.cookie)
	checkContent(t, page, `aria-sort="ascending"`, `>Connected</td>`,
		`/devices?order=desc&amp;presence=Connected&#43;at&#43;last&#43;poll&amp;search=lab&amp;sort=addresses`,
		`src="https://static.ui.com/fingerprint/0/4488_101x101.png"`, `referrerpolicy="no-referrer"`, "Ownership conflict",
		`name="sort" value="addresses"`, `name="order" value="asc"`)
	body := page.Body.String()
	if strings.Index(body, ">lab-desk</a>") >= strings.Index(body, ">lab-camera</a>") ||
		strings.Contains(body, ">lab-old</a>") || strings.Contains(body, "<small>Publishable</small>") ||
		strings.Count(body, `class="device-sort"`) != 7 || strings.Count(body, `aria-sort=`) != 1 {
		t.Fatalf("unexpected sorted address table: %s", body)
	}
	if !strings.Contains(page.Header().Get("Content-Security-Policy"), "img-src 'self' "+unifiArtworkOrigin) {
		t.Fatal("Devices CSP does not allow UniFi artwork")
	}
	for _, path := range []string{
		"/devices?sort=addresses&order=desc", "/devices?sort=seen", "/devices?sort=unknown&order=desc",
	} {
		page := request(f.handler, "GET", path, nil, f.cookie)
		checkContent(t, page, ">lab-camera</a>", ">lab-desk</a>", ">Last connected 2 hours ago</td>")
		if body := page.Body.String(); strings.Index(body, ">lab-camera</a>") >= strings.Index(body, ">lab-desk</a>") {
			t.Errorf("%s did not put lab-camera first", path)
		}
	}

	page = request(f.handler, "POST", "/devices/poll?search=lab&sort=addresses&order=desc", url.Values{"csrf": {f.csrf}}, f.cookie)
	checkContent(t, page, "UniFi poll requested", `aria-sort="descending"`, `name="search" type="search" value="lab"`)
	if !strings.Contains(page.Header().Get("Content-Security-Policy"), unifiArtworkOrigin) {
		t.Fatal("poll response CSP does not allow UniFi artwork")
	}
}

func TestQueryHistorySummaryAndDetails(t *testing.T) {
	f := setup(t)
	f.login(t)
	response := request(f.handler, http.MethodGet, "/query-log", nil, f.cookie)
	checkContent(t, response, `>Time (UTC)</th>`, `scope="rowgroup"`, `>00:00:00</time>`, `>23:59:59</time>`,
		`>laptop.home.arpa</span><small class="secondary muted">192.0.2.2</small>`, `<td>2001:db8::2</td>`,
		`class="query-badge allowed">Allowed`, `class="query-badge blocked">Blocked`, `>HTTPS</td>`,
		`>1.00 ms</td>`, `>123 µs</td>`, `<details class="query-detail">`,
		`<dt>Allow rule</dt><dd>adguard-filters-1/@@||js.monitor.azure.com^|</dd>`, `<dt>Source</dt><dd>upstream</dd>`,
		`<dt>DNS response</dt><dd>NOERROR</dd>`, `<dt>Cache</dt><dd>miss</dd>`)
	body := response.Body.String()
	if strings.Count(body, `scope="rowgroup"`) != 2 || strings.Contains(body, `>Node</th>`) || strings.Contains(body, ">fixture</td>") {
		t.Fatal("expected separate UTC dates and no node column")
	}
	for _, tc := range []struct{ outcome, want, excluded string }{
		{"Allowed", "js.monitor.azure.com.", "blocked.test."},
		{"Blocked", "blocked.test.", "js.monitor.azure.com."},
	} {
		filtered := request(f.handler, http.MethodGet, "/query-log?outcome="+tc.outcome, nil, f.cookie)
		checkContent(t, filtered, tc.want)
		if strings.Contains(filtered.Body.String(), tc.excluded) {
			t.Errorf("%s filter included %s", tc.outcome, tc.excluded)
		}
	}
}

func TestQueryClientNameFromInventory(t *testing.T) {
	ip := netip.MustParseAddr("2001:db8::1")
	state := config.State{Devices: map[string]config.Device{"client": {
		Canonical: "workstation",
		Addresses: []config.Address{{IP: ip, Active: true}},
	}}}
	s := server{hooks: Hooks{Select: func(netip.Addr, time.Time) contract.Selection {
		return contract.Selection{Device: "client", Precedence: "subnet", Confidence: "observed"}
	}}}
	for _, tc := range []struct{ client, want string }{
		{ip.String(), "workstation"},
		{"2001:db8::2", ""},
		{"client-0123456789abcdef", ""},
	} {
		if got := s.queryClientName(tc.client, state, time.Now()); got != tc.want {
			t.Errorf("client %q got hostname %q, want %q", tc.client, got, tc.want)
		}
	}
}

func TestQueryBadge(t *testing.T) {
	cases := []struct {
		origin, cache string
		code          int
		want          string
	}{
		{"local", "", dns.RcodeSuccess, "local"},
		{"local", "", dns.RcodeNameError, "local"},
		{"cache", "hit", dns.RcodeSuccess, "cache"},
		{"cache", "hit", dns.RcodeNameError, "cache"},
		{"upstream", "miss", dns.RcodeSuccess, "upstream"},
		{"upstream", "miss", dns.RcodeNameError, "upstream"},
		{"policy", "hit", dns.RcodeNameError, "blocked"},
		{"policy", "", dns.RcodeRefused, "blocked"},
		{"upstream", "miss", dns.RcodeServerFailure, "error"},
		{"cache", "hit", dns.RcodeServerFailure, "error"},
		{"server", "", dns.RcodeFormatError, "error"},
	}
	for _, tc := range cases {
		entry := querylog.Entry{Origin: tc.origin, RCode: tc.code, Cache: tc.cache}
		if got := queryBadge(entry).Kind; got != tc.want {
			t.Errorf("%s %s (cache %q): got %q, want %q", tc.origin, entry.RCodeLabel(), tc.cache, got, tc.want)
		}
	}
}

func TestConsoleStylesheetVersion(t *testing.T) {
	f := setup(t)
	css := request(f.handler, http.MethodGet, "/assets/admin.css", nil)
	if css.Code != http.StatusOK || !strings.HasPrefix(css.Header().Get("Content-Type"), "text/css") ||
		!strings.Contains(css.Body.String(), ".service-grid") {
		t.Fatal("missing embedded admin stylesheet")
	}
	versionedPath := fmt.Sprintf("/assets/admin.css?v=%x", sha256.Sum256(css.Body.Bytes()))
	login := request(f.handler, http.MethodGet, "/login", nil)
	checkContent(t, login, `href="`+versionedPath+`"`)
	versioned := request(f.handler, http.MethodGet, versionedPath, nil)
	if versioned.Code != http.StatusOK || versioned.Body.String() != css.Body.String() ||
		!strings.Contains(versioned.Header().Get("Cache-Control"), "immutable") {
		t.Fatal("versioned stylesheet differs from embedded CSS or has the wrong cache policy")
	}
	stale := request(f.handler, http.MethodGet, "/assets/admin.css?v=previous", nil)
	if css.Header().Get("Cache-Control") != "no-store" || stale.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("served cacheable CSS under an unversioned or stale URL")
	}
}

func TestRevisionConflictsCSRFSettingsAndAudit(t *testing.T) {
	f := setup(t)
	f.login(t)
	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		form.Set("csrf", f.csrf)
		return request(f.handler, "POST", path, form, f.cookie)
	}
	missing := request(f.handler, "POST", "/devices/poll", url.Values{"csrf": {"missing"}}, f.cookie)
	if missing.Code != http.StatusForbidden || f.triggers != 0 {
		t.Fatal("controller poll bypassed CSRF")
	}
	poll := post("/devices/poll", url.Values{})
	checkContent(t, poll, "UniFi poll requested")

	if invalid := post("/settings/import", url.Values{"revision": {"4"}, "settings": {`{"version":1,"password":"leak"}`}}); invalid.Code != http.StatusBadRequest || f.state.Revision != 4 {
		t.Fatalf("invalid settings were imported: %d", invalid.Code)
	}
	updated := post("/devices/edit", url.Values{"revision": {"4"}, "id": {"cam-01"}, "settings": {`{"group":"IoT","unpublish":true}`}})
	if updated.Code != http.StatusSeeOther || updated.Header().Get("X-Marco-Revision") != "5" || !f.state.Desired.Devices["cam-01"].Unpublish {
		t.Fatalf("edit failed: %d", updated.Code)
	}
	replayed := post("/devices/edit", url.Values{"revision": {"4"}, "id": {"cam-01"}, "settings": {`{"group":"IoT"}`}})
	if replayed.Code != http.StatusConflict || !strings.Contains(replayed.Body.String(), `name="revision" value="4"`) ||
		!strings.Contains(replayed.Body.String(), "Revision 5 is active") || !f.state.Desired.Devices["cam-01"].Unpublish {
		t.Fatalf("stale edit could overwrite a newer configuration: %d", replayed.Code)
	}
	off := post("/blocklists/toggle", url.Values{"revision": {"5"}, "id": {"fixture"}, "enabled": {"false"}})
	if off.Code != http.StatusSeeOther || f.state.Desired.Subscriptions["fixture"].Enabled {
		t.Fatalf("list could not be disabled: %d", off.Code)
	}

	exported := request(f.handler, "GET", "/settings/export", nil, f.cookie)
	var desired config.Desired
	if err := json.Unmarshal(exported.Body.Bytes(), &desired); err != nil || desired.Version != config.Version ||
		exported.Header().Get("X-Marco-Revision") != "6" || strings.Contains(exported.Body.String(), "fixture-digest") ||
		strings.Contains(exported.Body.String(), "recuper") {
		t.Fatalf("invalid portable settings export: %s, %v", exported.Body.String(), err)
	}

	var count int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM admin_audit WHERE operation = 'edit-device' AND result = 'success' AND revision = 5 AND account = 'local:operator'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("edit audit missing: %v", err)
	}
	logout := post("/logout", url.Values{})
	if logout.Code != http.StatusSeeOther || request(f.handler, "GET", "/devices", nil, f.cookie).Code != http.StatusSeeOther {
		t.Fatal("logout did not revoke the session")
	}
}

func TestAddDefaultsAndAssignDeviceGroup(t *testing.T) {
	f := setup(t)
	f.login(t)
	f.state.Desired.Groups["trusted"] = config.Policy{Mode: config.Unfiltered}
	f.state.Desired.Subscriptions["custom-adaway"] = config.Subscription{
		URL: config.DefaultSubscriptions()["adguard-filters-2"].URL,
	}
	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		form.Set("csrf", f.csrf)
		form.Set("revision", fmt.Sprint(f.state.Revision))
		return request(f.handler, "POST", path, form, f.cookie)
	}
	if added := post("/policies/defaults", url.Values{}); added.Code != http.StatusSeeOther {
		t.Fatalf("adding groups returned %d", added.Code)
	}
	for group := range config.DefaultGroups() {
		if _, ok := f.state.Desired.Groups[group]; !ok {
			t.Fatalf("default group %q missing", group)
		}
	}
	if f.state.Desired.Groups["trusted"].Mode != config.Unfiltered {
		t.Fatal("adding defaults changed an existing group policy")
	}
	form := request(f.handler, "GET", "/devices/edit?id=cam-01", nil, f.cookie)
	checkContent(t, form, `<select name="group">`, `<option value="IoT" selected>`, `<option value="mobile">`)
	assignment := post("/devices/edit", url.Values{
		"id": {"cam-01"}, "group-picker": {"1"}, "group": {"mobile"}, "settings": {`{"unpublish":true}`},
	})
	if group := f.state.Desired.Devices["cam-01"]; assignment.Code != http.StatusSeeOther || group.Group != "mobile" || !group.Unpublish {
		t.Fatalf("wrong device settings after assignment: %+v, HTTP %d", group, assignment.Code)
	}
	removed := post("/devices/edit", url.Values{
		"id": {"cam-01"}, "group-picker": {"1"}, "group": {""}, "settings": {`{"unpublish":true}`},
	})
	if removed.Code != http.StatusSeeOther || f.state.Desired.Devices["cam-01"].Group != "" {
		t.Fatal("selecting Unassigned did not clear the group")
	}
	if added := post("/blocklists/defaults", url.Values{}); added.Code != http.StatusSeeOther {
		t.Fatalf("adding defaults returned %d", added.Code)
	}
	if !f.state.Desired.Subscriptions["adguard-filters-1"].Enabled {
		t.Fatal("enabled AdGuard DNS list is missing")
	}
	if _, duplicate := f.state.Desired.Subscriptions["adguard-filters-2"]; duplicate {
		t.Fatal("already configured AdAway URL was duplicated")
	}
}

func TestServiceCatalogBrowsing(t *testing.T) {
	catalog, err := config.LoadServiceCatalog("../../catalog/services.json")
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := filter.CompileService(catalog.Definitions()["amazon"])
	if err != nil {
		t.Fatal(err)
	}
	f := setupWithHooks(t, func(hooks *Hooks) {
		hooks.Catalog = catalog
		hooks.MatchService = func(id, name string, qtype uint16) filter.Match {
			if id != "amazon" {
				t.Errorf("tested the wrong service %s", id)
			}
			return matcher.Match(name, qtype)
		}
	})
	if icon := request(f.handler, http.MethodGet, "/services/icons/amazon", nil); icon.Code != http.StatusSeeOther {
		t.Fatalf("unauthenticated service image returned %d", icon.Code)
	}
	f.login(t)
	catalogPage := request(f.handler, http.MethodGet, "/services", nil, f.cookie)
	checkContent(t, catalogPage, "142 services", `href="/services?id=youtube"`)
	if count := strings.Count(catalogPage.Body.String(), `class="panel service-card"`); count != 142 {
		t.Fatalf("catalog rendered %d service cards", count)
	}
	if body := catalogPage.Body.String(); strings.Contains(body, `rel="next"`) ||
		strings.Contains(body, `<span class="muted">Revision `) {
		t.Fatal("catalog displayed pagination or the DNS revision badge")
	}
	streaming := request(f.handler, http.MethodGet, "/services?category=Streaming&page=2", nil, f.cookie)
	checkContent(t, streaming, "41 services", `href="/services?category=Streaming&amp;id=youtube"`)
	if count := strings.Count(streaming.Body.String(), `class="panel service-card"`); count != 41 {
		t.Fatalf("filtered catalog rendered %d service cards", count)
	}
	youtube := request(f.handler, http.MethodGet, "/services?category=Streaming&id=youtube", nil, f.cookie)
	checkContent(t, youtube, `href="/services?category=Streaming"`, `name="category" value="Streaming"`)
	index := request(f.handler, http.MethodGet, "/services?search=youtube", nil, f.cookie)
	checkContent(t, index, "YouTube", "1 service</p>", "/services/icons/youtube", `href="/services?id=youtube&amp;search=youtube"`)
	noMatches := request(f.handler, http.MethodGet, "/services?search=some-unmatched-service", nil, f.cookie)
	checkContent(t, noMatches, "No services match these filters.")
	detail := request(f.handler, http.MethodGet, "/services?id=amazon&host=s3.amazonaws.com&type=CNAME", nil, f.cookie)
	checkContent(t, detail, "Except CNAME queries", "No match for s3.amazonaws.com. CNAME", "awsdns-*.org")
	detail = request(f.handler, http.MethodGet, "/services?id=amazon&host=s3.amazonaws.com&type=A", nil, f.cookie)
	checkContent(t, detail, "s3.amazonaws.com. A matches", "amazonaws.com^$dnstype=~CNAME")
	filtered := request(f.handler, http.MethodGet, "/services?id=amazon&rule=except+cname", nil, f.cookie)
	checkContent(t, filtered, "1 of 201 rules", "Except CNAME queries")
	if strings.Contains(filtered.Body.String(), "awsdns-*.org") {
		t.Fatal("rule text filter retained an unrelated row")
	}
	icon := request(f.handler, http.MethodGet, "/services/icons/amazon", nil, f.cookie)
	if icon.Code != http.StatusOK || icon.Header().Get("Content-Type") != "image/svg+xml" ||
		!strings.Contains(icon.Header().Get("Content-Security-Policy"), "sandbox") || !strings.HasPrefix(icon.Body.String(), "<svg") {
		t.Fatal("service image was unavailable or served without isolation")
	}
}
