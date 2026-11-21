package inventory

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pridkett/marco/internal/config"
)

var fixtureTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func fixtureRow(mac, name string, ips ...string) Observation {
	row := Observation{
		MAC: mac, Reported: name, Network: "Fixture LAN", Present: true,
		UseObservationTime: true, CompleteIPv4: true,
	}
	for _, ip := range ips {
		row.Addresses = append(row.Addresses, netip.MustParseAddr(ip))
	}
	return row
}

func poll(t *testing.T, state *config.State, elapsed time.Duration, rows ...Observation) {
	t.Helper()
	err := Reconcile(state, Snapshot{
		Controller: "fixture-controller", Site: "default", ObservedAt: fixtureTime.Add(elapsed),
		Complete: true, Observations: rows,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func history(t *testing.T, state *config.State, id, ip string) config.Address {
	t.Helper()
	for _, address := range state.Devices[id].Addresses {
		if address.IP.String() == ip {
			return address
		}
	}
	t.Fatalf("no historical address %s for %s", ip, id)
	return config.Address{}
}

func TestReconcileKeepsNamesAndReplacesMovedAddresses(t *testing.T) {
	s := config.State{Desired: config.Defaults()}
	camera := fixtureRow("02-AA-00-00-00-01", "Hall Camera", "192.0.2.10", "2001:db8::10")
	camera.UniFiFingerprint = 4488
	cameraID := identityKey("fixture-controller", "default", "02:aa:00:00:00:01", "")
	poll(t, &s, 0, camera)
	if dev := s.Devices[cameraID]; dev.Canonical != "hall-camera" || !dev.FirstSeen.Equal(fixtureTime) {
		t.Fatalf("first observation: %+v", dev)
	}
	poll(t, &s, time.Minute)
	dev := s.Devices[cameraID]
	if dev.Connected || !dev.LastSeen.Equal(fixtureTime) || !dev.LastConnected.Equal(fixtureTime) ||
		!dev.LastPoll.Equal(fixtureTime.Add(time.Minute)) || dev.UniFiFingerprint != 4488 {
		t.Fatalf("absent device: %+v", dev)
	}
	if address := history(t, &s, cameraID, "192.0.2.10"); !address.Publish || address.Active {
		t.Fatalf("absent address should publish without a live binding: %+v", address)
	}

	newcomer := fixtureRow("02:aa:00:00:00:02", "Hall Camera", "192.0.2.90")
	newID := identityKey("fixture-controller", "default", newcomer.MAC, "")
	moved := fixtureRow(camera.MAC, "Renamed in UniFi", "192.0.2.11")
	old := camera
	old.Present, old.UseObservationTime = false, false
	old.LastSeen = fixtureTime
	poll(t, &s, 2*time.Minute, moved, old, newcomer)
	if got := s.Devices[cameraID]; got.Canonical != "hall-camera" || got.Reported != "Renamed in UniFi" ||
		!got.LastConnected.Equal(fixtureTime.Add(2*time.Minute)) || got.UniFiFingerprint != 4488 {
		t.Fatalf("reported change should preserve canonical name: %+v", got)
	}
	if got := s.Devices[newID].Canonical; !strings.HasPrefix(got, "hall-camera-") {
		t.Fatalf("duplicate name was not disambiguated: %s", got)
	}
	if address := history(t, &s, cameraID, "192.0.2.10"); !address.Superseded || address.Reassigned ||
		address.Publish || address.Active {
		t.Fatalf("old address should be historical after a confirmed move: %+v", address)
	}
	if address := history(t, &s, cameraID, "2001:db8::10"); !address.Publish || address.Active {
		t.Fatalf("IPv4 evidence cannot drop IPv6 publication or retain live IPv6 identity: %+v", address)
	}
	if address := history(t, &s, cameraID, "192.0.2.11"); !address.Publish || !address.Active ||
		address.Provenance != "observed" {
		t.Fatalf("new address should publish and bind: %+v", address)
	}
}

func TestOwnershipConflictAndReassignment(t *testing.T) {
	s := config.State{Desired: config.Defaults()}
	a := fixtureRow("02:aa:00:00:00:01", "Old Device", "192.0.2.10")
	b := fixtureRow("02:aa:00:00:00:02", "New Device", "192.0.2.10")
	idA := identityKey("fixture-controller", "default", a.MAC, "")
	idB := identityKey("fixture-controller", "default", b.MAC, "")
	poll(t, &s, 0, a)
	s.Desired.Devices = map[string]config.DeviceSettings{
		idA: {Pinned: []netip.Addr{netip.MustParseAddr("192.0.2.10")}, Group: "fixture-restricted"},
	}
	poll(t, &s, time.Minute, a, b)
	for _, id := range []string{idA, idB} {
		if addr := history(t, &s, id, "192.0.2.10"); !addr.Conflicted || addr.Publish {
			t.Fatalf("ambiguous address should be quarantined: %+v", addr)
		}
	}

	a.Present, a.UseObservationTime = false, false
	a.LastSeen = fixtureTime.Add(time.Minute)
	poll(t, &s, 2*time.Minute, a, b)
	if addr := history(t, &s, idA, "192.0.2.10"); !addr.Reassigned || !addr.Superseded ||
		addr.Publish || addr.Active || addr.Conflicted {
		t.Fatalf("confirmed reassignment did not displace the old mapping: %+v", addr)
	}
	if addr := history(t, &s, idB, "192.0.2.10"); !addr.Publish || !addr.Active || addr.Conflicted {
		t.Fatalf("new owner not published: %+v", addr)
	}
	if s.Desired.Devices[idB].Group != "" {
		t.Fatal("new device inherited the prior owner's policy")
	}
	poll(t, &s, 3*time.Minute, a)
	if addr := history(t, &s, idA, "192.0.2.10"); addr.Publish || addr.Active {
		t.Fatalf("old history reactivated a reassigned observation: %+v", addr)
	}
}

func TestUnknownHistoricalEvidenceCannotEstablishBinding(t *testing.T) {
	s := config.State{Desired: config.Defaults()}
	row := fixtureRow("02:aa:00:00:00:07", "Old Switch", "192.0.2.40")
	row.Present, row.UseObservationTime = false, false
	poll(t, &s, 0, row)
	id := identityKey("fixture-controller", "default", row.MAC, "")
	addr := history(t, &s, id, "192.0.2.40")
	if addr.Active || addr.Publish || !addr.LastSeen.IsZero() || !s.Devices[id].LastSeen.IsZero() {
		t.Fatalf("history without timestamps conferred freshness: %+v", addr)
	}
	before := s.SitePolls["fixture-controller/default"]
	err := Reconcile(&s, Snapshot{
		Controller: "fixture-controller", Site: "default", ObservedAt: fixtureTime.Add(time.Minute),
	})
	if err == nil || s.SitePolls["fixture-controller/default"] != before {
		t.Fatalf("partial report changed inventory freshness: %v", err)
	}
}

func TestMACChangeDoesNotInheritStableSourceIDAssignment(t *testing.T) {
	var state config.State
	a := fixtureRow("02:aa:00:00:00:01", "Laptop", "192.0.2.10")
	a.SourceID = "adapter-record"
	poll(t, &state, 0, a)
	b := a
	b.MAC = "02:aa:00:00:00:02"
	poll(t, &state, time.Minute, b)
	if len(state.Devices) != 2 {
		t.Fatalf("MAC rotation was merged: %+v", state.Devices)
	}
	b.MAC = ""
	err := Reconcile(&state, Snapshot{
		Controller: "fixture-controller", Site: "default", ObservedAt: fixtureTime.Add(2 * time.Minute),
		Complete: true, Observations: []Observation{b},
	})
	if err == nil {
		t.Fatal("reused source ID was accepted without a MAC")
	}
}

func TestExplicitInterfaceLinks(t *testing.T) {
	state := config.State{Desired: config.Defaults()}
	a := fixtureRow("02:aa:00:00:00:01", "Radio", "192.0.2.10")
	b := fixtureRow("02:aa:00:00:00:02", "Dock", "192.0.2.10")
	idA := identityKey("fixture-controller", "default", a.MAC, "")
	idB := identityKey("fixture-controller", "default", b.MAC, "")
	poll(t, &state, 0, a)
	state.Desired.Devices = map[string]config.DeviceSettings{idA: {Links: []string{idB}}}
	poll(t, &state, time.Minute, a, b)
	links, err := LinkTargets(&state)
	if err != nil || links[idB] != idA {
		t.Fatalf("linked primary = %s: %v", links[idB], err)
	}
	for _, id := range []string{idA, idB} {
		if address := history(t, &state, id, "192.0.2.10"); !address.Publish || address.Conflicted {
			t.Fatalf("operator-linked interface was quarantined: %+v", address)
		}
	}
	state.Desired.Devices[idB] = config.DeviceSettings{Links: []string{idA}}
	if err := Prepare(&state); err == nil {
		t.Fatal("accepted a cycle of explicit interface links")
	}
}

func TestReportedProxyDiscoveryNamesAreNotPublished(t *testing.T) {
	s := config.State{Desired: config.Defaults()}
	rogue := fixtureRow("02:aa:00:00:00:31", "WPAD", "192.0.2.31")
	tunnel := fixtureRow("02:aa:00:00:00:32", "isatap.example", "192.0.2.32")
	rogueID := identityKey("fixture-controller", "default", rogue.MAC, "")
	tunnelID := identityKey("fixture-controller", "default", tunnel.MAC, "")
	poll(t, &s, 0, rogue, tunnel)
	if got := s.Devices[rogueID].Canonical; got != "" {
		t.Fatalf("reported wpad name was published as %q", got)
	}
	if got := s.Devices[tunnelID].Canonical; got != "" {
		t.Fatalf("reported isatap name was published as %q", got)
	}

	// A name learned before the check is dropped unless an operator assigned it.
	legacy := s.Devices[rogueID]
	legacy.Canonical = "wpad"
	s.Devices[rogueID] = legacy
	if err := Prepare(&s); err != nil {
		t.Fatal(err)
	}
	if got := s.Devices[rogueID].Canonical; got != "" {
		t.Fatalf("stored wpad name was kept as %q", got)
	}
	s.Desired.Devices = map[string]config.DeviceSettings{rogueID: {Name: "wpad"}}
	if err := Prepare(&s); err != nil {
		t.Fatal(err)
	}
	if got := s.Devices[rogueID].Canonical; got != "wpad" {
		t.Fatalf("operator-assigned wpad name was not honored: %q", got)
	}
}
