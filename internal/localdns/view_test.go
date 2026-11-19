package localdns_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
	"github.com/pridkett/marco/internal/inventory"
	"github.com/pridkett/marco/internal/localdns"
	"github.com/pridkett/marco/internal/policy"
	"github.com/pridkett/marco/internal/runtime"
	"github.com/pridkett/marco/internal/store"
)

func zones() config.Desired {
	desired := config.Defaults()
	desired.Zones = []config.Zone{
		{Name: "fixture.test", Publish: true},
		{Name: "home.arpa", Private: true, Publish: true},
	}
	desired.Reverse = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8:fa:1::/64"),
	}
	return desired
}

func assertAnswer(t *testing.T, v contract.Local, name string, typ uint16, code int, answers, authority int) contract.LocalResult {
	t.Helper()
	got := v.Lookup(name, typ)
	if !got.Found || got.Code != code || len(got.Answer) != answers || len(got.Authority) != authority {
		t.Fatalf("Lookup(%s, %s) = %+v", name, dns.TypeToString[typ], got)
	}
	return got
}

func TestSplitPrivateAndReverseAnswers(t *testing.T) {
	desired := zones()
	desired.Records = []config.Record{
		{Name: "host.fixture.test", Type: "A", Value: "192.0.2.50"},
		{Name: "host.fixture.test", Type: "AAAA", Value: "2001:db8:fa:1::50"},
		{Name: "first.fixture.test", Type: "CNAME", Value: "second.fixture.test"},
		{Name: "second.fixture.test", Type: "CNAME", Value: "host.fixture.test"},
		{Name: "absent.fixture.test", Type: "CNAME", Value: "missing.fixture.test"},
		{Name: "absolute.fixture.test", Type: "CNAME", Value: "missing.other.test"},
		{Name: "external.fixture.test", Type: "CNAME", Value: "public.fixture.test", Public: true},
		{Name: "leak.fixture.test", Type: "CNAME", Value: "missing.home.arpa", Public: true},
		{Name: "nested.branch.home.arpa", Type: "A", Value: "192.0.2.51"},
	}
	view, err := localdns.Compile(&config.State{Revision: 12, Desired: desired})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		typ uint16
		ip  string
	}{{dns.TypeA, "192.0.2.50"}, {dns.TypeAAAA, "2001:db8:fa:1::50"}} {
		t.Run(dns.TypeToString[tt.typ], func(t *testing.T) {
			got := assertAnswer(t, view, "first.fixture.test.", tt.typ, dns.RcodeSuccess, 3, 0)
			if !got.Authoritative || !strings.HasSuffix(got.Answer[2].String(), tt.ip) {
				t.Fatalf("incorrect terminal RRset: %+v", got)
			}
			reverse, _ := dns.ReverseAddr(tt.ip)
			got = assertAnswer(t, view, reverse, dns.TypePTR, dns.RcodeSuccess, 1, 0)
			if ptr := got.Answer[0].(*dns.PTR).Ptr; ptr != "host.fixture.test." {
				t.Fatalf("PTR = %s", ptr)
			}
		})
	}
	assertAnswer(t, view, "host.fixture.test.", dns.TypeTXT, dns.RcodeSuccess, 0, 1)
	assertAnswer(t, view, "branch.home.arpa.", dns.TypeA, dns.RcodeSuccess, 0, 1)
	if view.Lookup("outside.fixture.test.", dns.TypeA).Found {
		t.Fatal("a genuine split-zone miss cannot fall through")
	}
	for name, authority := range map[string]string{
		"not-there.home.arpa.":      "home.arpa.",
		"77.2.0.192.in-addr.arpa.":  "2.0.192.in-addr.arpa.",
		"bad.2.0.192.in-addr.arpa.": "2.0.192.in-addr.arpa.",
	} {
		got := assertAnswer(t, view, name, dns.TypeA, dns.RcodeNameError, 0, 1)
		if soa := got.Authority[0].(*dns.SOA); soa.Serial != 12 || soa.Hdr.Name != authority {
			t.Fatalf("incorrect authority for %s: %s", name, soa)
		}
	}
	got := assertAnswer(t, view, "absent.fixture.test.", dns.TypeA, dns.RcodeNameError, 1, 1)
	if got.PublicTarget != "" {
		t.Fatalf("unresolved local alias was marked for forwarding: %+v", got)
	}
	got = assertAnswer(t, view, "absolute.fixture.test.", dns.TypeA, dns.RcodeNameError, 1, 1)
	if got.PublicTarget != "" {
		t.Fatalf("an absolute target was forwarded without an explicit public setting: %+v", got)
	}
	if len(view.Issues()) != 3 {
		t.Fatalf("unresolved alias warnings: %+v", view.Issues())
	}
	got = assertAnswer(t, view, "external.fixture.test.", dns.TypeA, dns.RcodeSuccess, 1, 0)
	if got.PublicTarget != "public.fixture.test." {
		t.Fatalf("explicit public target = %q", got.PublicTarget)
	}
	got = assertAnswer(t, view, "leak.fixture.test.", dns.TypeA, dns.RcodeNameError, 1, 1)
	if got.PublicTarget != "" {
		t.Fatal("an explicit flag overrode private authority")
	}
}

func TestRejectInvalidLocalEdits(t *testing.T) {
	records := [][]config.Record{
		{{Name: "z.fixture.test", Type: "CNAME", Value: "z.fixture.test"}},
		{{Name: "a.fixture.test", Type: "CNAME", Value: "b.fixture.test"}, {Name: "b.fixture.test", Type: "CNAME", Value: "a.fixture.test"}},
		{{Name: "a.fixture.test", Type: "CNAME", Value: "example.net"}, {Name: "A.FIXTURE.TEST.", Type: "A", Value: "192.0.2.10"}},
		{{Name: "a.fixture.test", Type: "CNAME", Value: "example.net"}, {Name: "a.fixture.test", Type: "CNAME", Value: "example.org"}},
		{{Name: "a.fixture.test", Type: "AAAA", Value: "192.0.2.10"}},
		{{Name: "1.2.0.192.in-addr.arpa", Type: "PTR", Value: "one.fixture.test"}, {Name: "1.2.0.192.in-addr.arpa", Type: "PTR", Value: "two.fixture.test"}},
	}
	for _, test := range records {
		desired := zones()
		desired.Records = test
		if _, err := localdns.Compile(&config.State{Desired: desired}); err == nil {
			t.Errorf("accepted invalid records %+v", test)
		}
	}
}

func compile(state *config.State, _ *contract.View) (*contract.View, error) {
	local, err := localdns.Compile(state)
	if err != nil {
		return nil, err
	}
	policies, err := policy.Compile(state, nil)
	if err != nil {
		return nil, err
	}
	return &contract.View{Local: local, Policies: policies}, nil
}

func TestPublishSurvivesRestartReassignmentRemovesDNSAndPolicy(t *testing.T) {
	ctx := t.Context()
	directory := t.TempDir()
	desired := zones()
	desired.Groups = map[string]config.Policy{"restricted": {Mode: config.LocalOnly}}
	db, err := store.Open(ctx, directory, desired)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	p, err := runtime.Open(ctx, db, compile)
	if err != nil {
		t.Fatal(err)
	}
	seen := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	ip := netip.MustParseAddr("192.0.2.10")
	unwanted := netip.MustParseAddr("192.0.2.11")
	poll := func(at time.Time, rows ...inventory.Observation) {
		t.Helper()
		_, err := p.Update(ctx, 0, func(state *config.State) error {
			return inventory.Reconcile(state, inventory.Snapshot{
				Controller: "fixture-controller", Site: "default", ObservedAt: at,
				Complete: true, Observations: rows,
			})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	owner := inventory.Observation{MAC: "02:AA:00:00:00:01", Reported: "Workshop", Present: true,
		UseObservationTime: true, CompleteIPv4: true, Addresses: []netip.Addr{ip, unwanted}}
	poll(seen, owner)
	var id string
	for key := range p.Snapshot().Devices {
		id = key
	}
	_, err = p.Update(ctx, p.Revision(), func(state *config.State) error {
		state.Desired.Devices = map[string]config.DeviceSettings{
			id: {Group: "restricted", Pinned: []netip.Addr{ip}, Aliases: []string{"workbench.fixture.test"}},
		}
		state.Desired.Suppressions = []config.Suppression{{Name: "workshop", Address: unwanted}}
		// The paired rule preserves this independent admin record at a
		// different owner while filtering the learned address and alias.
		state.Desired.Records = []config.Record{{Name: "emergency.home.arpa", Type: "A", Value: "192.0.2.11"}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	before := p.View()
	if selected := before.Policies.Select(ip, seen.Add(4*time.Minute)); selected.Policy.Mode != config.LocalOnly {
		t.Fatalf("fresh identity did not select restricted policy: %+v", selected)
	}
	if selected := before.Policies.Select(ip, seen.Add(6*time.Minute)); selected.Policy.Mode != config.Filtered {
		t.Fatalf("expired identity retained restricted policy: %+v", selected)
	}
	assertAnswer(t, before.Local, "workbench.fixture.test.", dns.TypeA, dns.RcodeSuccess, 1, 0)
	assertAnswer(t, before.Local, "emergency.home.arpa.", dns.TypeA, dns.RcodeSuccess, 1, 0)
	rev, _ := dns.ReverseAddr(ip.String())
	otherRev, _ := dns.ReverseAddr(unwanted.String())
	if ptr := assertAnswer(t, before.Local, otherRev, dns.TypePTR, dns.RcodeSuccess, 1, 0).Answer[0].(*dns.PTR); ptr.Ptr != "emergency.home.arpa." {
		t.Fatalf("paired suppression exposed a learned PTR: %s", ptr)
	}

	poll(seen.Add(time.Minute)) // A complete connected list omits the device.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = store.Open(ctx, directory, desired)
	if err != nil {
		t.Fatal(err)
	}
	p, err = runtime.Open(ctx, db, compile)
	if err != nil {
		t.Fatal(err)
	}
	after := p.View()
	assertAnswer(t, after.Local, "workbench.fixture.test.", dns.TypeA, dns.RcodeSuccess, 1, 0)
	assertAnswer(t, after.Local, rev, dns.TypePTR, dns.RcodeSuccess, 1, 0)
	if selected := after.Policies.Select(ip, seen.Add(2*time.Minute)); selected.Policy.Mode != config.Filtered {
		t.Fatalf("offline device retained source policy across restart: %+v", selected)
	}

	newOwner := inventory.Observation{MAC: "02:aa:00:00:00:02", Reported: "Transformer", Present: true,
		UseObservationTime: true, CompleteIPv4: true, Addresses: []netip.Addr{ip}}
	poll(seen.Add(2*time.Minute), newOwner)
	after = p.View()
	for _, hidden := range []string{"workshop.fixture.test.", "workbench.fixture.test."} {
		got := assertAnswer(t, after.Local, hidden, dns.TypeA, dns.RcodeNameError, 0, 1)
		if !got.Suppressed {
			t.Fatalf("reassigned name %s can leak upstream", hidden)
		}
	}
	if ptr := assertAnswer(t, after.Local, rev, dns.TypePTR, dns.RcodeSuccess, 1, 0).Answer[0].(*dns.PTR); ptr.Ptr != "transformer.fixture.test." {
		t.Fatalf("PTR still identifies old owner: %s", ptr)
	}
	if selected := after.Policies.Select(ip, seen.Add(2*time.Minute)); selected.Policy.Mode != config.Filtered || selected.Device == id {
		t.Fatalf("new owner inherited prior identity: %+v", selected)
	}
	if view := after.Local.(*localdns.View); len(view.Issues()) == 0 || view.Published(id) {
		t.Fatalf("displaced pin lacked publication warning: %+v", view.Issues())
	}
	_, err = p.Update(ctx, p.Revision(), func(state *config.State) error {
		settings := state.Desired.Devices[id]
		settings.Aliases = nil
		state.Desired.Devices[id] = settings
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	poll(seen.Add(3*time.Minute), newOwner)
	if p.View().Local.Lookup("workbench.fixture.test.", dns.TypeA).Found {
		t.Fatal("deleted managed alias survived publication")
	}
}

func TestLegacySeedStaysExactUntilOwnershipConfirmed(t *testing.T) {
	desired := zones()
	ip := netip.MustParseAddr("192.0.2.14")
	state := config.State{
		Desired: desired,
		Devices: map[string]config.Device{
			"legacy": {ID: "legacy", Legacy: true, LegacyOwner: "legacy.fixture.test.",
				Addresses: []config.Address{{IP: ip, Publish: true}}},
		},
	}
	old, err := localdns.Compile(&state)
	if err != nil {
		t.Fatal(err)
	}
	assertAnswer(t, old, "legacy.fixture.test.", dns.TypeA, dns.RcodeSuccess, 1, 0)
	assertAnswer(t, old, "legacy.home.arpa.", dns.TypeA, dns.RcodeNameError, 0, 1)
	err = inventory.Reconcile(&state, inventory.Snapshot{
		Controller: "fixture", Site: "default", Complete: true, ObservedAt: time.Now(),
		Observations: []inventory.Observation{{MAC: "02:aa:00:00:00:06", Reported: "live", Present: true,
			UseObservationTime: true, Addresses: []netip.Addr{ip}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := localdns.Compile(&state)
	if err != nil {
		t.Fatal(err)
	}
	if record := assertAnswer(t, got, "legacy.fixture.test.", dns.TypeA, dns.RcodeNameError, 0, 1); !record.Suppressed {
		t.Fatal("displaced legacy owner was allowed to fall through")
	}
	// Compiled data remains intact when a later candidate is applied.
	assertAnswer(t, old, "legacy.fixture.test.", dns.TypeA, dns.RcodeSuccess, 1, 0)
}

func TestNonAlignedReverseScopesAndAlternatePTRs(t *testing.T) {
	desired := zones()
	desired.Reverse = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.128/25"),
		netip.MustParsePrefix("2001:db8:fa:1:8000::/65"),
	}
	desired.Devices = map[string]config.DeviceSettings{"fixed": {
		Name: "Fixed Device",
		Pinned: []netip.Addr{
			netip.MustParseAddr("192.0.2.130"),
			netip.MustParseAddr("2001:db8:fa:1:8000::10"),
		},
	}}
	for _, multiple := range []bool{false, true} {
		desired.MultiplePTRs = multiple
		view, err := localdns.Compile(&config.State{Desired: desired})
		if err != nil {
			t.Fatal(err)
		}
		for _, ip := range []string{"192.0.2.130", "2001:db8:fa:1:8000::10"} {
			reverse, _ := dns.ReverseAddr(ip)
			count := 1
			if multiple {
				count = 2
			}
			got := assertAnswer(t, view, reverse, dns.TypePTR, dns.RcodeSuccess, count, 0)
			if primary := got.Answer[0].(*dns.PTR).Ptr; primary != "fixed-device.fixture.test." {
				t.Fatalf("unexpected primary PTR %s", primary)
			}
		}
		for _, ip := range []string{"192.0.2.131", "2001:db8:fa:1:8000::11"} {
			reverse, _ := dns.ReverseAddr(ip)
			assertAnswer(t, view, reverse, dns.TypePTR, dns.RcodeNameError, 0, 1)
		}
		for _, ip := range []string{"192.0.2.40", "2001:db8:fa:1:4000::11"} {
			reverse, _ := dns.ReverseAddr(ip)
			if view.Lookup(reverse, dns.TypePTR).Found {
				t.Fatalf("reverse authority escaped its CIDR at %s", reverse)
			}
		}
	}
}

func TestConfirmedNameCanReplaceLegacySeed(t *testing.T) {
	state := config.State{
		Desired: zones(), Devices: map[string]config.Device{
			"legacy": {ID: "legacy", Legacy: true, LegacyOwner: "laptop.fixture.test.", Reported: "laptop.fixture.test.",
				Addresses: []config.Address{{IP: netip.MustParseAddr("192.0.2.14"), Publish: true}}},
		},
	}
	old, err := localdns.Compile(&state)
	if err != nil {
		t.Fatal(err)
	}
	assertAnswer(t, old, "laptop.fixture.test.", dns.TypeA, dns.RcodeSuccess, 1, 0)
	if err := inventory.Reconcile(&state, inventory.Snapshot{
		Controller: "fixture", Site: "default", Complete: true, ObservedAt: time.Now(),
		Observations: []inventory.Observation{{MAC: "02:aa:00:00:00:07", Reported: "laptop", Present: true,
			UseObservationTime: true, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.14")}}},
	}); err != nil {
		t.Fatal(err)
	}
	view, err := localdns.Compile(&state)
	if err != nil {
		t.Fatal(err)
	}
	assertAnswer(t, view, "laptop.fixture.test.", dns.TypeA, dns.RcodeSuccess, 1, 0)
	assertAnswer(t, view, "laptop.home.arpa.", dns.TypeA, dns.RcodeSuccess, 1, 0)
}
