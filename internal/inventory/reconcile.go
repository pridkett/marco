// Package inventory models and reconciles complete read-only controller polls.
package inventory

import (
	"crypto/sha256"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/pridkett/marco/internal/config"
)

const SourceMaxAge = 5 * time.Minute

type Observation struct {
	MAC, SourceID, Reported, Hostname, Network string
	Addresses                                  []netip.Addr
	LastSeen                                   time.Time
	Present                                    bool
	// UseObservationTime is allowed only for a documented connected-only
	// endpoint, or explicit current online state.
	UseObservationTime         bool
	CompleteIPv4, CompleteIPv6 bool
}

type Snapshot struct {
	Controller, Site string
	ObservedAt       time.Time
	Complete         bool
	Observations     []Observation
}

type evidence struct {
	seen       time.Time
	provenance string
	live       bool
}

type observedDevice struct {
	identity  config.Device
	seen      time.Time
	present   bool
	complete  map[bool]bool
	addresses map[netip.Addr]evidence
}

func validAddress(addr netip.Addr) bool {
	return addr.IsValid() && addr.Zone() == "" && (addr.IsGlobalUnicast() || addr.IsLoopback())
}

func identityKey(controller, site, mac, sourceID string) string {
	kind, value := "source", sourceID
	if mac != "" {
		kind, value = "mac", mac
	}
	sum := sha256.Sum256([]byte(controller + "\x00" + site + "\x00" + kind + "\x00" + value))
	return fmt.Sprintf("unifi-%x", sum[:16])
}

func normalizeMAC(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	mac, err := net.ParseMAC(strings.TrimSpace(raw))
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
		return "", fmt.Errorf("invalid device MAC %q", raw)
	}
	return mac.String(), nil
}

func observationEvidence(obs Observation, now time.Time) evidence {
	seen, provenance := obs.LastSeen, "controller"
	if seen.IsZero() {
		provenance = "history"
		if obs.Present && obs.UseObservationTime {
			seen, provenance = now, "observed"
		}
	}
	if seen.After(now) {
		// Clamp slight clock skew without granting freshness to invalid dates.
		if seen.Sub(now) > time.Minute {
			seen, provenance = time.Time{}, "history"
		} else {
			seen = now
		}
	}
	return evidence{
		seen: seen, provenance: provenance,
		live: obs.Present && !seen.IsZero() && now.Sub(seen) <= SourceMaxAge,
	}
}

func collect(state *config.State, report Snapshot) (map[string]*observedDevice, error) {
	idByMAC := make(map[string]string)
	idBySource := make(map[string]string)
	ambiguousSource := make(map[string]bool)
	for id, dev := range state.Devices {
		if dev.Controller == report.Controller && dev.Site == report.Site {
			if dev.MAC != "" {
				idByMAC[dev.MAC] = id
			}
			if dev.SourceID != "" {
				if prior := idBySource[dev.SourceID]; prior != "" && prior != id {
					ambiguousSource[dev.SourceID] = true
				}
				idBySource[dev.SourceID] = id
			}
		}
	}
	items := make(map[string]*observedDevice)
	for _, row := range report.Observations {
		mac, err := normalizeMAC(row.MAC)
		if err != nil {
			return nil, err
		}
		row.SourceID = strings.TrimSpace(row.SourceID)
		if strings.ContainsRune(row.SourceID, 0) ||
			(mac == "" && (row.SourceID == "" || ambiguousSource[row.SourceID])) {
			return nil, fmt.Errorf("UniFi row lacks a stable device identity")
		}
		id := idByMAC[mac]
		if id == "" && !ambiguousSource[row.SourceID] {
			id = idBySource[row.SourceID]
			if previous := state.Devices[id].MAC; mac != "" && previous != "" && previous != mac {
				// A new MAC is a new identity, even when the controller reuses
				// a client row ID for it.
				id = ""
			}
		}
		if id == "" {
			id = identityKey(report.Controller, report.Site, mac, row.SourceID)
		}
		if mac != "" {
			idByMAC[mac] = id
		}
		if row.SourceID != "" {
			if prior := idBySource[row.SourceID]; prior != "" && prior != id {
				ambiguousSource[row.SourceID] = true
				if items[prior] != nil {
					return nil, fmt.Errorf("UniFi snapshot reuses a source ID for different MAC addresses")
				}
			}
			idBySource[row.SourceID] = id
		}
		item := items[id]
		if item == nil {
			item = &observedDevice{
				identity: config.Device{ID: id, Controller: report.Controller, Site: report.Site},
				complete: make(map[bool]bool), addresses: make(map[netip.Addr]evidence),
			}
			items[id] = item
		}
		if mac != "" && item.identity.MAC != "" && item.identity.MAC != mac {
			return nil, fmt.Errorf("UniFi snapshot reuses a source ID for different MAC addresses")
		}
		if mac != "" {
			item.identity.MAC = mac
		}
		if row.SourceID != "" && (item.identity.SourceID == "" || row.Present && !item.present) {
			item.identity.SourceID = row.SourceID
		}
		ev := observationEvidence(row, report.ObservedAt)
		if row.Present && !item.present || ev.seen.After(item.seen) || item.identity.Reported == "" {
			item.identity.Reported = strings.TrimSpace(row.Reported)
			item.identity.Hostname = strings.TrimSpace(row.Hostname)
			item.identity.Network = strings.TrimSpace(row.Network)
		}
		item.present = item.present || row.Present
		if ev.seen.After(item.seen) {
			item.seen = ev.seen
		}
		for _, address := range row.Addresses {
			if !validAddress(address) {
				return nil, fmt.Errorf("device %q has invalid reported address %s", id, address)
			}
			address = address.Unmap()
			prior, exists := item.addresses[address]
			if !exists || ev.live && !prior.live || ev.live == prior.live && ev.seen.After(prior.seen) {
				item.addresses[address] = ev
			}
		}
		if ev.live {
			item.complete[true] = item.complete[true] || row.CompleteIPv4
			item.complete[false] = item.complete[false] || row.CompleteIPv6
		}
	}
	return items, nil
}

func updateAddress(old config.Address, ip netip.Addr, ev evidence) config.Address {
	old.IP = ip
	old.Active = ev.live
	if ev.seen.After(old.LastSeen) || old.Provenance == "" {
		old.LastSeen, old.Provenance = ev.seen, ev.provenance
	}
	if ev.live {
		old.Publish, old.Superseded, old.Reassigned, old.Conflicted = true, false, false, false
	}
	return old
}

func applyObservation(device config.Device, item *observedDevice, at time.Time) config.Device {
	identity := item.identity
	if identity.MAC == "" {
		identity.MAC = device.MAC
	}
	if identity.SourceID == "" {
		identity.SourceID = device.SourceID
	}
	identity.FirstSeen = device.FirstSeen
	if identity.FirstSeen.IsZero() {
		identity.FirstSeen = at
	}
	identity.LastSeen = device.LastSeen
	if item.seen.After(identity.LastSeen) {
		identity.LastSeen = item.seen
	}
	identity.LastPoll, identity.Connected = at, item.present
	identity.Canonical = device.Canonical
	prior := make(map[netip.Addr]config.Address, len(device.Addresses))
	moved := make(map[bool]bool)
	for _, address := range device.Addresses {
		prior[address.IP.Unmap()] = address
	}
	for ip, ev := range item.addresses {
		if ev.live {
			moved[ip.Is4()] = true
		}
		prior[ip] = updateAddress(prior[ip], ip, ev)
	}
	for ip, address := range prior {
		if !item.addresses[ip].live {
			address.Active = false
			if moved[ip.Is4()] && item.complete[ip.Is4()] {
				address.Publish = false
				address.Superseded = true
			}
		}
		prior[ip] = address
	}
	for _, ip := range slices.SortedFunc(maps.Keys(prior), netip.Addr.Compare) {
		identity.Addresses = append(identity.Addresses, prior[ip])
	}
	return identity
}

func controls(device config.Device, report Snapshot) bool {
	return device.Controller == report.Controller && device.Site == report.Site
}

func currentlyClaimed(device config.Device, address config.Address, now time.Time) bool {
	return device.Connected && address.Active && !device.Legacy &&
		!address.LastSeen.IsZero() && !device.LastPoll.IsZero() &&
		now.Sub(address.LastSeen) <= SourceMaxAge && now.Sub(device.LastPoll) <= SourceMaxAge
}

func reconcileOwnership(state *config.State, now time.Time) error {
	links, err := LinkTargets(state)
	if err != nil {
		return err
	}
	allClaims := make(map[netip.Addr]map[string]struct{})
	for id, dev := range state.Devices {
		for _, address := range dev.Addresses {
			if !currentlyClaimed(dev, address, now) {
				continue
			}
			ip := address.IP.Unmap()
			if allClaims[ip] == nil {
				allClaims[ip] = make(map[string]struct{})
			}
			allClaims[ip][links[id]] = struct{}{}
		}
	}
	for id, dev := range state.Devices {
		positions := make(map[netip.Addr]int, len(dev.Addresses))
		for i, address := range dev.Addresses {
			ip := address.IP.Unmap()
			positions[ip] = i
			claimants := allClaims[ip]
			if len(claimants) == 0 {
				continue
			}
			_, owns := claimants[links[id]]
			switch {
			case len(claimants) > 1:
				address.Conflicted = true
				address.Publish = false
			case !owns:
				address.Superseded = true
				address.Reassigned = true
				address.Conflicted = false
				address.Active = false
				address.Publish = false
			case currentlyClaimed(dev, address, now):
				address.Conflicted = false
				address.Publish = true
			}
			dev.Addresses[i] = address
		}
		// Retain durable conflict evidence even for a pinned address that never
		// appeared in a live poll for this device.
		for _, ip := range state.Desired.Devices[id].Pinned {
			ip = ip.Unmap()
			if _, exists := positions[ip]; exists {
				continue
			}
			claimants := allClaims[ip]
			if _, owns := claimants[links[id]]; owns && len(claimants) == 1 || len(claimants) == 0 {
				continue
			}
			dev.Addresses = append(dev.Addresses, config.Address{
				IP: ip, Provenance: "pinned", Superseded: len(claimants) == 1,
				Reassigned: len(claimants) == 1, Conflicted: len(claimants) > 1,
			})
		}
		state.Devices[id] = dev
	}
	return nil
}

// Reconcile applies an accepted complete site snapshot to a publisher candidate.
// Missing addresses lose source identity immediately. Publication of the last
// usable address survives absence until a move or competing live claim.
func Reconcile(state *config.State, report Snapshot) error {
	if !report.Complete || report.ObservedAt.IsZero() ||
		report.Controller == "" || report.Site == "" ||
		strings.ContainsAny(report.Controller+report.Site, "/\x00") {
		return fmt.Errorf("incomplete or invalid UniFi site snapshot")
	}
	key := report.Controller + "/" + report.Site
	if previous := state.SitePolls[key]; !previous.IsZero() && !report.ObservedAt.After(previous) {
		return nil
	}
	items, err := collect(state, report)
	if err != nil {
		return err
	}
	if state.Devices == nil {
		state.Devices = make(map[string]config.Device)
	}
	for id, device := range state.Devices {
		if _, present := items[id]; present || !controls(device, report) {
			continue
		}
		device.Connected, device.LastPoll = false, report.ObservedAt
		for i := range device.Addresses {
			device.Addresses[i].Active = false
		}
		state.Devices[id] = device
	}
	for id, item := range items {
		state.Devices[id] = applyObservation(state.Devices[id], item, report.ObservedAt)
	}
	if err := Prepare(state); err != nil {
		return err
	}
	if err := reconcileOwnership(state, report.ObservedAt); err != nil {
		return err
	}
	if state.SitePolls == nil {
		state.SitePolls = make(map[string]time.Time)
	}
	state.SitePolls[key] = report.ObservedAt
	return nil
}
