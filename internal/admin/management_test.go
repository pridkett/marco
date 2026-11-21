package admin

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/auth"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
	"github.com/pridkett/marco/internal/policy"
	"github.com/pridkett/marco/internal/querylog"
	"github.com/pridkett/marco/internal/runtime"
	"github.com/pridkett/marco/internal/store"
)

func TestManagementAPI(t *testing.T) {
	const origin = "https://marco.test"
	const resource = origin + mcpPath
	issuer, mint := managementIssuer(t)
	read := mint("at+jwt", resource, managementRead, time.Now().Add(time.Hour))
	write := mint("at+jwt", resource, managementRead+" "+managementWrite, time.Now().Add(time.Hour))

	ctx := t.Context()
	db, err := store.Open(ctx, t.TempDir(), config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	manager, err := auth.New(ctx, db, auth.Settings{
		PublicURL: origin, Issuer: issuer, ClientID: "console", ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := runtime.Open(ctx, db, func(state *config.State, _ *contract.View) (*contract.View, error) {
		return &contract.View{}, policy.Validate(state.Desired)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	rev, err := p.Update(ctx, 0, func(state *config.State) error {
		state.Devices = map[string]config.Device{
			"cam": {ID: "cam", Controller: "unifi", Site: "test", Connected: true,
				Addresses: []config.Address{{IP: netip.MustParseAddr("192.0.2.10"), Active: true}}},
			"speaker": {ID: "speaker", Controller: "unifi", Site: "test", Connected: true},
		}
		for i := range 1001 {
			id := fmt.Sprintf("bulk-%04d", i)
			state.Devices[id] = config.Device{ID: id}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	historyPath := filepath.Join(t.TempDir(), "history.sqlite")
	history, err := querylog.Open(historyPath, querylog.Settings{Enabled: true, Anonymize: true, AnonymizationKey: []byte("test-anonymization-key")})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, item := range []struct {
		name string
		kind uint16
	}{
		{"blocked.example.test.", dns.TypeA}, {"other.example.test.", dns.TypeAAAA},
		{"also-blocked.example.test.", dns.TypeA}, {"type-zero.example.test.", 0},
	} {
		history.Observe(contract.Event{
			Input:  contract.Input{Name: item.name, Type: item.kind, Time: now, Peer: netip.MustParseAddr("192.0.2.10")},
			Result: contract.Result{Origin: "policy", RCode: dns.RcodeNameError},
		})
	}
	for range 1001 {
		history.Observe(contract.Event{
			Input: contract.Input{Name: "bulk.example.test.", Type: dns.TypeTXT, Time: now.Add(-time.Hour)},
		})
	}
	if err := history.Close(); err != nil {
		t.Fatal(err)
	}
	history, err = querylog.Open(historyPath, querylog.Settings{Enabled: true, Anonymize: true, AnonymizationKey: []byte("test-anonymization-key")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { history.Close() })
	hooks := Hooks{
		Snapshot: p.Snapshot, Update: p.Update, Revision: p.Revision,
		Preview: func(in contract.Input) (contract.Selection, contract.Result) {
			if in.Name != "blocked.example.test." || in.Type != dns.TypeA || in.Peer.String() != "192.0.2.10" {
				t.Errorf("preview input = %+v", in)
			}
			return contract.Selection{Group: "family"}, contract.Result{Origin: "policy", Rule: "test-rule", RCode: dns.RcodeNameError}
		},
	}
	check := func(handler http.Handler, method, path, token, body string, status int, headers ...string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, origin+path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		for i := 0; i < len(headers); i += 2 {
			r.Header.Set(headers[i], headers[i+1])
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s %s: HTTP %d, want %d. Body %s", method, path, w.Code, status, w.Body.String())
		}
		return w
	}
	check(New(manager, history, hooks), "POST", mcpPath, read, "{}", 404)
	hooks.ManagementAPI = true
	check(New(nil, history, hooks), "POST", mcpPath, read, "{}", 404)
	handler := New(manager, history, hooks)
	api := func(method, path, token, body string, status int, headers ...string) *httptest.ResponseRecorder {
		t.Helper()
		return check(handler, method, path, token, body, status, headers...)
	}
	metadata := api("GET", resourceMetadata+mcpPath, "", "", 200)
	if !strings.Contains(metadata.Body.String(), resource) || !strings.Contains(metadata.Body.String(), issuer) {
		t.Fatalf("incorrect resource metadata: %s", metadata.Body)
	}
	initial := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`
	w := api("POST", mcpPath, "", initial, 401)
	if !strings.Contains(w.Header().Get("WWW-Authenticate"), origin+resourceMetadata+mcpPath) {
		t.Fatalf("missing discovery challenge: %v", w.Header())
	}
	for _, token := range []string{
		mint("JWT", resource, managementRead, time.Now().Add(time.Hour)),
		mint("at+jwt", origin+"/elsewhere", managementRead, time.Now().Add(time.Hour)),
		mint("at+jwt", resource, managementRead, time.Now().Add(-time.Hour)),
		read[:len(read)-10] + "AAAAAAAAAA",
	} {
		api("GET", managementPrefix+"/dashboard", token, "", 401)
	}
	api("GET", managementPrefix+"/dashboard", mint("at+jwt", resource, managementWrite, time.Now().Add(time.Hour)), "", 403)
	api("POST", mcpPath, read, initial, 403, "Origin", "https://elsewhere.test")
	api("POST", mcpPath, read, initial, 200, "Origin", origin)
	api("GET", mcpPath, read, "", 405)
	api("POST", mcpPath, read, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, 202)

	discover := `{"jsonrpc":"2.0","id":"d","method":"server/discover","params":{"_meta":{
		"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},
		"io.modelcontextprotocol/clientCapabilities":{}}}}`
	w = api("POST", mcpPath, read, discover, 200, mcpVersionHeader, currentMCPVersion, "Mcp-Method", "server/discover")
	requireJSON(t, w, `"supportedVersions":["2026-07-28","2025-11-25"`)
	w = api("POST", mcpPath, read, discover, 400, mcpVersionHeader, currentMCPVersion, "Mcp-Method", "tools/list")
	requireJSON(t, w, `"code":-32020`)
	modernCall := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"get_policies","_meta":{
		"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},
		"io.modelcontextprotocol/clientCapabilities":{}}}}`
	w = api("POST", mcpPath, read, modernCall, 200, mcpVersionHeader, currentMCPVersion, "Mcp-Method", "tools/call", "Mcp-Name", "get_policies")
	requireJSON(t, w, `"resultType":"complete"`)
	requireJSON(t, w, `"structuredContent":{"revision":`+jsonText(rev))
	w = api("POST", mcpPath, read, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, 200)
	for _, name := range []string{"get_dashboard", "search_query_log", "test_policy", "get_policies", "update_policies", "list_clients"} {
		requireJSON(t, w, `"name":"`+name+`"`)
	}

	w = api("GET", managementPrefix+"/dashboard?range=15m", read, "", 200)
	requireJSON(t, w, `"counts":{"queries":4`)
	requireJSON(t, w, `"upstreamBlocks":0`)
	requireJSON(t, w, `"upstreamBlocked":[]`)
	w = api("GET", managementPrefix+"/query-log?type=A&question=blocked&outcome=blocked&limit=1", read, "", 200)
	var page historyData
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Entries) != 1 ||
		page.Entries[0].Name != "also-blocked.example.test." || page.Entries[0].Client == "192.0.2.10" || page.Next == 0 {
		t.Fatalf("unexpected history page: %s (%v)", w.Body, err)
	}
	w = api("GET", managementPrefix+"/query-log?type=A&before="+jsonText(page.Next), read, "", 200)
	requireJSON(t, w, `"name":"blocked.example.test."`)
	w = api("GET", managementPrefix+"/query-log?type=type0", read, "", 200)
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Entries) != 1 || page.Entries[0].Type != 0 {
		t.Fatalf("unexpected TYPE0 history page: %s (%v)", w.Body, err)
	}
	api("GET", managementPrefix+"/query-log?type=TYPE65536", read, "", 400)
	w = api("GET", managementPrefix+"/devices?search=192.0.2.10", read, "", 200)
	requireJSON(t, w, `"id":"cam"`)
	w = api("GET", managementPrefix+"/devices?presence=connected&limit=1", read, "", 200)
	requireJSON(t, w, `"next":"cam"`)
	w = api("GET", managementPrefix+"/devices?presence=connected&limit=1&after=cam", read, "", 200)
	requireJSON(t, w, `"id":"speaker"`)
	w = api("POST", mcpPath, read, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
		"name":"test_policy","arguments":{"client":"192.0.2.10","question":"https://blocked.example.test/a?q=123"}}}`, 200)
	requireJSON(t, w, `"structuredContent":{"client":"192.0.2.10","question":"blocked.example.test."`)
	w = api("GET", managementPrefix+"/policies", read, "", 200)
	requireJSON(t, w, `"revision":`+jsonText(rev))
	update := `{"revision":` + jsonText(rev) + `,"groups":{"test":{"mode":"local-only"}}}`
	api("PATCH", managementPrefix+"/policies", read, update, 403)
	call := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"update_policies","arguments":` + update + `}}`
	w = api("POST", mcpPath, read, call, 403)
	if !strings.Contains(w.Header().Get("WWW-Authenticate"), managementWrite) {
		t.Fatal("write scope missing from challenge")
	}
	w = api("POST", mcpPath, write, call, 200)
	requireJSON(t, w, `"structuredContent":{"revision":`+jsonText(rev+1))
	api("PATCH", managementPrefix+"/policies", write, update, 409)
	api("PATCH", managementPrefix+"/policies", write,
		`{"revision":`+jsonText(rev+1)+`,"groups":{"test":{"mode":"invalid"}}}`, 422)
	if current := p.Snapshot(); current.Revision != rev+1 || current.Desired.Groups["test"].Mode != config.LocalOnly {
		t.Fatalf("invalid or stale edit modified live state: %+v", current.Desired.Groups)
	}
	var count int
	if err := db.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_audit
		WHERE account = ? AND operation = 'api-edit-policies' AND result = 'success' AND revision = ?`, issuer+"|operator", rev+1).Scan(&count); err != nil || count != 1 {
		t.Fatalf("audit count = %d, error = %v", count, err)
	}

	api("GET", managementPrefix+"/query-log?limit=201", read, "", 400)
	api("GET", managementPrefix+"/devices?limit=201", read, "", 400)
	hooks.ManagementMaxPageSize = 1000
	handler = New(manager, history, hooks)
	w = api("POST", mcpPath, read, `{"jsonrpc":"2.0","id":10,"method":"tools/list"}`, 200)
	if n := strings.Count(w.Body.String(), `"maximum":1000,"default":50`); n != 2 {
		t.Fatalf("expected the configured maximum in both MCP list schemas, found %d", n)
	}
	w = api("GET", managementPrefix+"/query-log?type=TXT&limit=1000", read, "", 200)
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Entries) != 1000 || page.Next == 0 {
		t.Fatalf("expected 1000 queries and a cursor, got %d queries with cursor %d (%v)", len(page.Entries), page.Next, err)
	}
	w = api("GET", managementPrefix+"/query-log?type=TXT&limit=1000&before="+jsonText(page.Next), read, "", 200)
	page = historyData{}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Entries) != 1 || page.Next != 0 {
		t.Fatalf("expected 1 remaining query, got %d queries with cursor %d (%v)", len(page.Entries), page.Next, err)
	}
	w = api("POST", mcpPath, read, `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{
		"name":"list_clients","arguments":{"search":"bulk-","limit":1000}}}`, 200)
	var clients struct {
		Result struct {
			Content devicesData `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &clients); err != nil || len(clients.Result.Content.Devices) != 1000 || clients.Result.Content.Next != "bulk-0999" {
		t.Fatalf("expected 1000 devices and a cursor, got %d devices with cursor %q (%v)",
			len(clients.Result.Content.Devices), clients.Result.Content.Next, err)
	}
	api("GET", managementPrefix+"/query-log?limit=1001", read, "", 400)

	hooks.ManagementMaxPageSize = 2
	handler = New(manager, history, hooks)
	w = api("GET", managementPrefix+"/query-log?type=TXT", read, "", 200)
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Entries) != 2 || page.Next == 0 {
		t.Fatalf("expected omitted limit to respect the cap, got %d queries with cursor %d (%v)", len(page.Entries), page.Next, err)
	}
}

func requireJSON(t *testing.T, w *httptest.ResponseRecorder, fragment string) {
	t.Helper()
	if !strings.Contains(w.Body.String(), fragment) {
		t.Fatalf("expected %s in %s", fragment, w.Body)
	}
}

func jsonText(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func managementIssuer(t *testing.T) (string, func(typ, audience, scope string, expiry time.Time) string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeManagementJSON(w, 200, map[string]any{
				"issuer": base, "authorization_endpoint": base + "/authorize",
				"token_endpoint": base + "/token", "jwks_uri": base + "/keys",
			})
		case "/keys":
			writeManagementJSON(w, 200, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, KeyID: "test", Algorithm: "EdDSA"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(issuer.Close)
	transport := http.DefaultTransport
	http.DefaultTransport = issuer.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = transport })
	return issuer.URL, func(typ, audience, scope string, expiry time.Time) string {
		t.Helper()
		sign, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
		if err != nil {
			t.Fatal(err)
		}
		token, err := sign.Sign([]byte(jsonText(map[string]any{
			"iss": issuer.URL, "sub": "operator", "aud": audience, "exp": expiry.Unix(), "scope": scope,
		})))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := token.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
}
