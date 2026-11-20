package policy

import (
	"net/netip"
	"testing"
	"time"

	"github.com/pridkett/marco/internal/config"
)

func TestPolicyPrecedenceAndIdentityExpiry(t *testing.T) {
	now := time.Now().UTC()
	live := netip.MustParseAddr("192.0.2.10")
	moved := netip.MustParseAddr("192.0.2.11")
	gateway := netip.MustParseAddr("192.0.2.1")
	svc := []string{"fixture-video"}
	empty := []string{}
	d := config.Defaults()
	d.Default.Rules = []config.Rule{{ID: "global-deny", Name: "blocked.test", Suffix: true}}
	d.Groups = map[string]config.Policy{"children": {
		Mode: config.LocalOnly, Services: &svc,
		Rules: []config.Rule{{ID: "group-deny", Name: "example.test", Suffix: true}, {ID: "group-allow", Name: "allowed.example.test", Allow: true}},
	}}
	d.Devices = map[string]config.DeviceSettings{"child": {Group: "children", Policy: config.Policy{
		Mode: config.Filtered, Services: &empty, Rules: []config.Rule{
			{ID: "device-allow", Name: "blocked.test", Allow: true, Suffix: true},
			{ID: "device-deny", Name: "sub.blocked.test", Suffix: true},
			{ID: "device-deny-tie", Name: "blocked.test", Suffix: true},
		},
	}}}
	d.Services = map[string]config.Service{"fixture-video": {Version: "1", Domains: []config.Rule{{Name: "video.test", Suffix: true}}}}
	d.Assignments = []config.Assignment{
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Group: "children"},
		{Prefix: netip.MustParsePrefix("fd00::/64"), Group: "children"},
		{Prefix: netip.PrefixFrom(gateway, 32), Policy: config.Policy{Mode: config.Unfiltered}},
		{Prefix: netip.PrefixFrom(moved, 32), Device: "child"},
	}
	d.Subscriptions = map[string]config.Subscription{"sample": {URL: "https://lists.example/test", Enabled: true}}
	state := config.State{Desired: d, Devices: map[string]config.Device{
		"child": {ID: "child", Connected: true, LastPoll: now, Addresses: []config.Address{
			{IP: live, Active: true, LastSeen: now}, {IP: moved, Reassigned: true, Superseded: true},
		}},
	}, Artifacts: map[string]config.Artifact{"sample": {Source: d.Subscriptions["sample"], Digest: "fixture",
		Body: []byte("||listed.test^\n@@||allowed.listed.test^\n0.0.0.0 exact.test\n")}}}
	if err := Validate(d); err != nil {
		t.Fatal(err)
	}
	e, err := Compile(&state, nil)
	if err != nil {
		t.Fatal(err)
	}
	child := e.Select(live, now)
	if child.Policy.Mode != config.Filtered || child.Precedence != "device" || child.Policy.Services == nil || len(*child.Policy.Services) != 0 {
		t.Fatalf("client override failed %+v", child)
	}
	for name, rule := range map[string]string{"blocked.test.": "device-deny-tie", "sub.blocked.test.": "device-deny", "allowed.example.test.": "group-allow"} {
		if got := e.Manual(child, name); got.Rule != rule {
			t.Fatalf("manual decision for %s = %+v, want %s", name, got, rule)
		}
	}
	for name, blocked := range map[string]bool{
		"video.test.": false, "x.listed.test.": true, "x.allowed.listed.test.": false, "exact.test.": true, "x.exact.test.": false, "notlisted.test.": false,
	} {
		if got := e.External(child, name, 1, now); got.Blocked != blocked {
			t.Fatalf("external decision for %s = %+v", name, got)
		}
	}
	for _, addr := range []netip.Addr{live, moved, netip.MustParseAddr("fd00::222")} {
		if s := e.Select(addr, now.Add(6*time.Minute)); s.Precedence != "subnet" || s.Policy.Mode != config.LocalOnly {
			t.Fatalf("fallback for %s = %+v", addr, s)
		}
	}
	if s := e.Select(gateway, now); s.Precedence != "static" || s.Policy.Mode != config.Unfiltered {
		t.Fatalf("gateway policy = %+v", s)
	}
	if s := e.Select(netip.MustParseAddr("198.51.100.10"), now); s.Policy.Mode != config.Filtered {
		t.Fatalf("unassigned default = %+v", s)
	}
}
