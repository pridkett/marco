package admin

import (
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/auth"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
	"github.com/pridkett/marco/internal/policy"
	"github.com/pridkett/marco/internal/runtime"
	"github.com/pridkett/marco/internal/store"
)

var editBasePattern = regexp.MustCompile(`name="edit-base" value="([^"]+)"`)

func TestServiceFilterConflictsOnlyWithRelevantSettings(t *testing.T) {
	desired := config.Defaults()
	desired.Services = map[string]config.Service{
		"video": {Version: "1", Domains: []config.Rule{{Name: "video.example.test"}}},
		"chat":  {Version: "1", Domains: []config.Rule{{Name: "chat.example.test"}}},
	}
	desired.Groups = map[string]config.Policy{"kids": {}, "trusted": {}}
	desired.Devices = map[string]config.DeviceSettings{"cam-01": {Group: "kids"}}
	desired.Subscriptions = map[string]config.Subscription{"fixture": {Enabled: true, File: "list.txt"}}
	db, err := store.Open(t.Context(), t.TempDir(), desired)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	pub, err := runtime.Open(t.Context(), db, func(s *config.State, _ *contract.View) (*contract.View, error) {
		engine, err := policy.Compile(s, nil)
		return &contract.View{Policies: engine}, err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()
	password, err := auth.HashPassword([]byte("local recovery password"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := auth.New(t.Context(), db, auth.Settings{
		PublicURL: "https://marco.test", Username: "operator", PasswordHash: password,
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{handler: New(manager, nil, Hooks{Snapshot: pub.Snapshot, Revision: pub.Revision, Update: pub.Update})}
	f.login(t)
	const path = "/services/filter"
	formFor := func(target string) url.Values {
		t.Helper()
		page := request(f.handler, "GET", path+"?target="+url.QueryEscape(target), nil, f.cookie)
		checkContent(t, page, "Save service blocks")
		return url.Values{
			"csrf": {f.csrf}, "revision": {strconv.FormatUint(pub.Revision(), 10)},
			"target": {target}, "mode": {"custom"}, "edit-base": {editBase(page.Body.String())},
		}
	}
	groupA, groupB := formFor("group:kids"), formFor("group:kids")
	deviceA := formFor("device:cam-01")
	// Inventory and blocklist refreshes and a different group's policy are unrelated.
	for i := range 3 {
		if _, err := pub.Update(t.Context(), 0, func(s *config.State) error {
			s.SitePolls = map[string]time.Time{"fixture/site": time.Now().UTC().Add(time.Duration(i) * time.Minute)}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pub.Update(t.Context(), 0, func(s *config.State) error {
		s.Artifacts["fixture"] = config.Artifact{Source: desired.Subscriptions["fixture"], Digest: "new-list",
			Body: []byte("blocked.example.test\n")}
		s.Desired.Groups["trusted"] = config.Policy{Mode: config.Unfiltered}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	groupA["service"] = []string{"video"}
	if got := request(f.handler, "POST", path, groupA, f.cookie); got.Code != http.StatusSeeOther {
		t.Errorf("unrelated changes blocked a service save: HTTP %d", got.Code)
	}
	groupB["service"] = []string{"chat"}
	conflict := request(f.handler, "POST", path, groupB, f.cookie)
	for _, want := range []string{"Current service blocks", "Save reviewed selection", "video", "chat"} {
		if !strings.Contains(conflict.Body.String(), want) {
			t.Errorf("service conflict page missing %q", want)
		}
	}
	if conflict.Code != http.StatusConflict || !slices.Equal(serviceIDs(pub.Snapshot().Desired.Groups["kids"].Services), []string{"video"}) {
		t.Fatalf("stale group edit overwrote the current policy: HTTP %d", conflict.Code)
	}
	// A device inheriting this group opened its draft before the inherited list changed.
	if got := request(f.handler, "POST", path, deviceA, f.cookie); got.Code != http.StatusConflict {
		t.Errorf("changed inherited selection should require review: HTTP %d", got.Code)
	}
	groupB.Set("edit-base", editBase(conflict.Body.String()))
	if got := request(f.handler, "POST", path, groupB, f.cookie); got.Code != http.StatusSeeOther ||
		!slices.Equal(serviceIDs(pub.Snapshot().Desired.Groups["kids"].Services), []string{"chat"}) {
		t.Fatalf("review could not save the preserved draft: HTTP %d", got.Code)
	}

	first, second := formFor("group:kids"), formFor("group:kids")
	first.Set("service", "video")
	start, results := make(chan struct{}), make(chan int, 2)
	for _, form := range []url.Values{first, second} {
		go func() {
			<-start
			results <- request(f.handler, "POST", path, form, f.cookie).Code
		}()
	}
	close(start)
	codes := []int{<-results, <-results}
	slices.Sort(codes)
	if !slices.Equal(codes, []int{http.StatusSeeOther, http.StatusConflict}) {
		t.Errorf("two simultaneous saves from the same baseline returned %v", codes)
	}
}

func editBase(body string) string {
	if match := editBasePattern.FindStringSubmatch(body); match != nil {
		return match[1]
	}
	return ""
}

func TestSettingsEditorsCompareTheirOwnFields(t *testing.T) {
	f := setup(t)
	f.login(t)
	read := func(path, action string) url.Values {
		t.Helper()
		page := request(f.handler, "GET", path, nil, f.cookie)
		_, form, _ := strings.Cut(page.Body.String(), `action="`+action+`"`)
		form, _, _ = strings.Cut(form, "</form>")
		return url.Values{"csrf": {f.csrf}, "revision": {strconv.FormatUint(f.state.Revision, 10)}, "edit-base": {editBase(form)}}
	}
	device := read("/devices/edit?id=cam-01", "/devices/edit")
	device.Set("id", "cam-01")
	device.Set("settings", `{"group":"IoT","unpublish":true}`)
	subscription := read("/blocklists", "/blocklists/toggle")
	subscription.Set("id", "fixture")
	subscription.Set("enabled", "false")
	settingsImport := read("/settings", "/settings/import")
	settingsImport.Set("settings", `{"version":1}`)
	f.state.Desired.Default.Mode = config.Unfiltered
	f.state.Revision++
	if got := request(f.handler, "POST", "/devices/edit", device, f.cookie); got.Code != http.StatusSeeOther {
		t.Errorf("unrelated default policy edit blocked the device save: HTTP %d", got.Code)
	}
	if got := request(f.handler, "POST", "/blocklists/toggle", subscription, f.cookie); got.Code != http.StatusSeeOther {
		t.Errorf("unrelated device edit blocked the subscription toggle: HTTP %d", got.Code)
	}
	if got := request(f.handler, "POST", "/devices/edit", device, f.cookie); got.Code != http.StatusConflict {
		t.Errorf("stale device edit returned HTTP %d", got.Code)
	}
	if got := request(f.handler, "POST", "/settings/import", settingsImport, f.cookie); got.Code != http.StatusConflict {
		t.Errorf("would overwrite desired settings with a stale import: HTTP %d", got.Code)
	}
}

func TestServiceFilterGroupAndDevice(t *testing.T) {
	catalog, err := config.LoadServiceCatalog("../../catalog/services.json")
	if err != nil {
		t.Fatal(err)
	}
	f := setupWithHooks(t, func(h *Hooks) { h.Catalog = catalog })
	f.state.Desired.Services = map[string]config.Service{
		"fixture-video": {Version: "1", Domains: []config.Rule{{Name: "video.example.test", Suffix: true}}},
	}
	defaultBlocks := []string{"fixture-video"}
	f.state.Desired.Default.Services = &defaultBlocks
	const path = "/services/filter"
	const kids = path + "?target=group%3AKids"
	const camera = path + "?target=device%3Acam-01"
	if got := request(f.handler, "GET", path, nil); got.Code != http.StatusSeeOther {
		t.Fatalf("unauthenticated editor returned %d", got.Code)
	}
	f.login(t)
	checkContent(t, request(f.handler, "GET", "/services", nil, f.cookie), `href="/services/filter">Filter services`)
	checkContent(t, request(f.handler, "GET", path, nil, f.cookie), `<optgroup label="Groups">`, `<optgroup label="Devices">`, "porch-camera")

	rev := func() string { return strconv.FormatUint(f.state.Revision, 10) }
	create := request(f.handler, "POST", "/policies/groups", url.Values{
		"csrf": {f.csrf}, "revision": {rev()}, "group-name": {" Kids "},
	}, f.cookie)
	if _, ok := f.state.Desired.Groups["Kids"]; !ok || create.Code != http.StatusSeeOther {
		t.Fatalf("could not create group: %d %s", create.Code, create.Body.String())
	}
	checkContent(t, request(f.handler, "GET", kids, nil, f.cookie),
		`name="mode" value="inherit" checked`, "Follow the default policy. 1 blocked.", "YouTube", "fixture-video")
	assign := request(f.handler, "POST", "/devices/edit", url.Values{
		"csrf": {f.csrf}, "revision": {rev()}, "id": {"cam-01"}, "group-picker": {"1"}, "group": {"Kids"},
		"settings": {`{"unpublish":true,"aliases":["camera"]}`},
	}, f.cookie)
	if assign.Code != http.StatusSeeOther {
		t.Fatalf("could not assign device: %d %s", assign.Code, assign.Body.String())
	}
	stateDevice := f.state.Devices["cam-01"]
	stateDevice.Addresses[0].LastSeen = stateDevice.LastSeen
	f.state.Devices["cam-01"] = stateDevice
	f.state.Desired.Devices["manual"] = config.DeviceSettings{Group: "Kids"}
	f.state.Desired.Assignments = []config.Assignment{
		{Prefix: netip.MustParsePrefix("192.0.2.42/32"), Device: "manual"},
	}
	checkContent(t, request(f.handler, "GET", "/devices/edit?id=cam-01", nil, f.cookie),
		`href="`+camera+`">Filter services`)

	post := func(base, target, mode string, ids ...string) (int, string, string) {
		t.Helper()
		got := request(f.handler, "POST", path, url.Values{
			"csrf": {f.csrf}, "revision": {base}, "target": {target}, "mode": {mode}, "service": ids,
		}, f.cookie)
		return got.Code, got.Header().Get("Location"), got.Body.String()
	}
	oldRev := rev()
	status, location, body := post(oldRev, "group:Kids", "custom", "youtube", "fixture-video")
	if status != http.StatusSeeOther || location != path+"?applied="+rev()+"&target=group%3AKids" {
		t.Fatalf("group service edit failed: %d %s %s", status, location, body)
	}
	checkContent(t, request(f.handler, "GET", location, nil, f.cookie),
		"Applied revision "+rev()+".", `name="mode" value="custom" checked`, "2</strong> of 143 services blocked.")
	checkContent(t, request(f.handler, "GET", camera, nil, f.cookie),
		"Assigned to Kids.", "Follow the Kids group. 2 blocked.", `name="mode" value="inherit" checked`)

	assertBlocks := func(camera, manual bool) {
		t.Helper()
		state := f.state
		state.Artifacts = nil
		state.Desired.Services = catalog.Definitions()
		maps.Copy(state.Desired.Services, f.state.Desired.Services)
		engine, err := policy.Compile(&state, nil)
		if err != nil {
			t.Fatal(err)
		}
		for ip, want := range map[string]bool{"192.0.2.32": camera, "192.0.2.42": manual, "192.0.2.99": false} {
			now := time.Now()
			selected := engine.Select(netip.MustParseAddr(ip), now)
			if decision := engine.External(selected, "www.youtube.com.", dns.TypeA, now); decision.Blocked != want {
				t.Errorf("%s: service decision %+v, expected blocked=%v", ip, decision, want)
			}
		}
	}
	assertBlocks(true, true)

	status, _, body = post(oldRev, "device:cam-01", "custom", "youtube")
	if status != http.StatusConflict || !strings.Contains(body, `name="revision" value="`+oldRev+`"`) ||
		!strings.Contains(body, `href="`+camera+`">Reload current settings`) {
		t.Fatalf("stale edit lost its context or was accepted: %d", status)
	}
	status, _, _ = post(rev(), "device:cam-01", "custom")
	saved := f.state.Desired.Devices["cam-01"]
	if status != http.StatusSeeOther || saved.Policy.Services == nil || *saved.Policy.Services == nil ||
		len(*saved.Policy.Services) != 0 || saved.Group != "Kids" || !saved.Unpublish ||
		!slices.Equal(saved.Aliases, []string{"camera"}) {
		t.Fatalf("device override failed or changed other settings: %d %+v", status, saved)
	}
	assertBlocks(false, true)

	status, _, _ = post(rev(), "device:cam-01", "inherit")
	if status != http.StatusSeeOther || f.state.Desired.Devices["cam-01"].Policy.Services != nil {
		t.Fatal("device failed to restore inheritance")
	}
	assertBlocks(true, true)

	status, _, _ = post(rev(), "group:Kids", "inherit")
	if status != http.StatusSeeOther || f.state.Desired.Groups["Kids"].Services != nil {
		t.Fatal("group failed to restore inheritance")
	}
	assertBlocks(false, false)

	status, _, _ = post(rev(), "device:manual", "custom", "youtube")
	if status != http.StatusSeeOther {
		t.Fatalf("could not set a service to block for a manual device: %d", status)
	}
	assertBlocks(false, true)

	base := rev()
	for _, edit := range []struct{ target, mode, service string }{
		{"group:missing", "custom", "youtube"},
		{"device:missing", "custom", "youtube"},
		{"group:Kids", "custom", "missing"},
		{"group:Kids", "missing", "youtube"},
	} {
		if code, _, _ := post(base, edit.target, edit.mode, edit.service); code != http.StatusBadRequest || rev() != base {
			t.Errorf("invalid edit %+v returned %d or changed settings", edit, code)
		}
	}
	if got := request(f.handler, "POST", path, url.Values{
		"revision": {base}, "target": {"group:Kids"}, "mode": {"custom"}, "service": {"youtube"},
	}, f.cookie); got.Code != http.StatusForbidden || rev() != base {
		t.Fatalf("edit without CSRF returned %d or changed settings", got.Code)
	}
}
