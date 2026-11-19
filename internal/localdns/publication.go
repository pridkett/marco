package localdns

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/inventory"
)

type exclusions struct {
	names     map[string]bool
	addresses map[netip.Addr]bool
	pairs     map[string]map[netip.Addr]bool
}

func parseExclusions(rules []config.Suppression) (exclusions, error) {
	out := exclusions{make(map[string]bool), make(map[netip.Addr]bool), make(map[string]map[netip.Addr]bool)}
	for i, rule := range rules {
		var name string
		var err error
		if rule.Name != "" {
			if name, err = config.Name(rule.Name); err != nil {
				return exclusions{}, fmt.Errorf("suppressions[%d]: %w", i, err)
			}
		}
		ip := rule.Address.Unmap()
		if ip.Zone() != "" || (name == "" && !ip.IsValid()) {
			return exclusions{}, fmt.Errorf("invalid suppression at index %d", i)
		}
		switch {
		case name == "":
			out.addresses[ip] = true
		case !ip.IsValid():
			out.names[name] = true
		default:
			if out.pairs[name] == nil {
				out.pairs[name] = make(map[netip.Addr]bool)
			}
			out.pairs[name][ip] = true
		}
	}
	return out, nil
}

func (e exclusions) contains(name string, ip netip.Addr, labels []string) bool {
	if e.addresses[ip] || e.names[name] || e.pairs[name][ip] {
		return true
	}
	for _, label := range labels {
		if e.names[label] || e.pairs[label][ip] {
			return true
		}
	}
	return false
}

type publication struct {
	id      string
	names   []string
	aliases []string
	hidden  bool
}

type ptrCandidate struct {
	name     string
	priority int
}

func (v *View) publish(state *config.State, domains []string) error {
	links, err := inventory.LinkTargets(state)
	if err != nil {
		return err
	}
	excluded, err := parseExclusions(state.Desired.Suppressions)
	if err != nil {
		return err
	}
	ids := slices.Sorted(maps.Keys(state.Devices))
	byIP := make(map[netip.Addr]map[string]bool)
	pub := make(map[string]publication, len(ids))
	owners := make(map[string]string)
	manualOwners := make(map[string]bool)
	ptrs := make(map[netip.Addr][]ptrCandidate)
	for name, entry := range v.owners {
		manualOwners[name] = true
		for _, rtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			for _, rr := range entry.sets[rtype] {
				ip := rrIP(rr)
				ptrs[ip] = append(ptrs[ip], ptrCandidate{name, 0})
			}
		}
	}
	for _, id := range ids {
		dev := state.Devices[id]
		settings := state.Desired.Devices[id]
		p := publication{id: id, hidden: settings.Unpublish || state.Desired.Devices[links[id]].Unpublish}
		if dev.Legacy && dev.LegacyOwner != "" {
			name, err := config.Name(dev.LegacyOwner)
			if err != nil {
				return fmt.Errorf("legacy device %q: %w", id, err)
			}
			p.names = append(p.names, name)
		} else if dev.Canonical != "" {
			for _, domain := range domains {
				name, err := config.Name(dev.Canonical + "." + domain)
				if err != nil {
					return fmt.Errorf("device %q owner: %w", id, err)
				}
				p.names = append(p.names, name)
			}
		}
		for _, alias := range settings.Aliases {
			name, err := config.Name(alias)
			if err != nil {
				return fmt.Errorf("device %q alias: %w", id, err)
			}
			p.aliases = append(p.aliases, name)
		}
		pub[id] = p
		for _, name := range p.names {
			if previous := owners[name]; previous == "" || state.Devices[previous].Legacy && !dev.Legacy {
				owners[name] = id
			}
		}
		for _, address := range dev.Addresses {
			ip := address.IP.Unmap()
			if !ip.IsValid() || ip.Zone() != "" {
				return fmt.Errorf("device %q has invalid historical address %s", id, ip)
			}
			if address.Conflicted {
				v.issues = append(v.issues, Issue{Kind: "ambiguous-address", Device: id, Address: ip})
			}
			if !dev.Legacy && (address.Conflicted || address.Publish && !address.Superseded) {
				if byIP[ip] == nil {
					byIP[ip] = make(map[string]bool)
				}
				byIP[ip][links[id]] = true
			}
		}
	}
	// A canonical owner reserves its name before a configured alias can claim it.
	for _, id := range ids {
		for _, alias := range pub[id].aliases {
			if owners[alias] == "" {
				owners[alias] = id
			}
		}
	}
	for _, id := range ids {
		dev, settings := state.Devices[id], state.Desired.Devices[id]
		addresses := make(map[netip.Addr]bool)
		displaced := make(map[netip.Addr]bool)
		for _, address := range dev.Addresses {
			ip := address.IP.Unmap()
			if address.Publish || address.Superseded || address.Conflicted {
				addresses[ip] = address.Publish && !address.Superseded && !address.Conflicted
			}
			displaced[ip] = address.Reassigned || address.Conflicted
		}
		for _, pin := range settings.Pinned {
			pin = pin.Unmap()
			owners := byIP[pin]
			blocked := displaced[pin] || len(owners) > 1 || len(owners) == 1 && !owners[links[id]]
			if blocked {
				v.issues = append(v.issues, Issue{Kind: "pinned-address-conflict", Device: id, Address: pin})
			}
			addresses[pin] = !blocked
		}
		destinations := []publication{pub[id]}
		if links[id] != id {
			destinations = append(destinations, pub[links[id]])
		}
		labels := learnedLabels(dev)
		for _, dest := range destinations {
			if err := v.publishDevice(dest, pub[id].hidden, labels, addresses, excluded, manualOwners, owners, ptrs); err != nil {
				return err
			}
		}
	}
	if err := v.publishPTRs(ptrs, manualOwners, byIP, state.Desired.MultiplePTRs); err != nil {
		return err
	}
	slices.SortFunc(v.issues, compareIssue)
	v.issues = slices.CompactFunc(v.issues, func(a, b Issue) bool { return a == b })
	return nil
}

func compareIssue(a, b Issue) int {
	if c := strings.Compare(a.Kind, b.Kind); c != 0 {
		return c
	}
	if c := strings.Compare(a.Name, b.Name); c != 0 {
		return c
	}
	if c := strings.Compare(a.Device, b.Device); c != 0 {
		return c
	}
	return a.Address.Compare(b.Address)
}

func learnedLabels(device config.Device) []string {
	var labels []string
	for _, name := range []string{device.Canonical, device.Reported, device.Hostname} {
		if name, err := config.Name(name); err == nil {
			labels = append(labels, name)
		} else if label := inventory.Label(name); label != "" {
			labels = append(labels, label+".")
		}
	}
	return labels
}

func rrIP(rr dns.RR) netip.Addr {
	switch record := rr.(type) {
	case *dns.A:
		ip, _ := netip.AddrFromSlice(record.A)
		return ip.Unmap()
	case *dns.AAAA:
		ip, _ := netip.AddrFromSlice(record.AAAA)
		return ip
	default:
		return netip.Addr{}
	}
}

func (v *View) addLearned(name, id string, ip netip.Addr, manual map[string]bool, owners map[string]string) (bool, error) {
	if manual[name] {
		v.issues = append(v.issues, Issue{Kind: "manual-owner-conflict", Name: name, Device: id, Address: ip})
		return false, nil
	}
	if owners[name] != id {
		v.issues = append(v.issues, Issue{Kind: "learned-owner-conflict", Name: name, Device: id, Address: ip})
		return false, nil
	}
	if err := v.add(addressRR(name, ip, v.dynamicTTL), false, true); err != nil {
		return false, err
	}
	v.published[id] = true
	return true, nil
}

func (v *View) publishDevice(dest publication, unpublished bool, labels []string, addresses map[netip.Addr]bool, excluded exclusions,
	manual map[string]bool, owners map[string]string, ptrs map[netip.Addr][]ptrCandidate) error {
	names := append(slices.Clone(dest.names), dest.aliases...)
	if unpublished || dest.hidden {
		for _, name := range names {
			v.hidden[name] = true
		}
		return nil
	}
	for _, name := range names {
		if excluded.contains(name, netip.Addr{}, labels) {
			v.hidden[name] = true
		}
	}
	for _, ip := range slices.SortedFunc(maps.Keys(addresses), netip.Addr.Compare) {
		usable := addresses[ip]
		// An alias inherits the suppression of the mappings it represents.
		// Publish addresses directly so an excluded IP cannot leak via CNAME.
		aliased := len(dest.names) == 0
		for index, name := range dest.names {
			if !usable || excluded.contains(name, ip, labels) {
				v.hidden[name] = true
				continue
			}
			aliased = true
			added, err := v.addLearned(name, dest.id, ip, manual, owners)
			if err != nil {
				return err
			}
			if added {
				ptrs[ip] = append(ptrs[ip], ptrCandidate{name, index + 1})
			}
		}
		for _, name := range dest.aliases {
			if !usable || !aliased || excluded.contains(name, ip, labels) {
				v.hidden[name] = true
				continue
			}
			added, err := v.addLearned(name, dest.id, ip, manual, owners)
			if err != nil {
				return err
			}
			if added && len(dest.names) == 0 {
				ptrs[ip] = append(ptrs[ip], ptrCandidate{name, len(v.zones) + 1})
			}
		}
	}
	return nil
}

func (v *View) publishPTRs(candidates map[netip.Addr][]ptrCandidate, manual map[string]bool, byIP map[netip.Addr]map[string]bool, multiple bool) error {
	for _, ip := range slices.SortedFunc(maps.Keys(candidates), netip.Addr.Compare) {
		options := candidates[ip]
		slices.SortFunc(options, func(a, b ptrCandidate) int {
			if a.priority != b.priority {
				return a.priority - b.priority
			}
			return strings.Compare(a.name, b.name)
		})
		for _, option := range options {
			if option.priority != 0 {
				break
			}
			for device := range byIP[ip] {
				v.issues = append(v.issues, Issue{Kind: "manual-address-overlap", Name: option.name, Device: device, Address: ip})
			}
		}
		name, err := dns.ReverseAddr(ip.String())
		if err != nil || v.reverseZone(name) == "" || manual[name] {
			continue
		}
		if !multiple {
			options = options[:1]
		}
		ttl := v.dynamicTTL
		if options[0].priority == 0 {
			ttl = v.staticTTL
		}
		for _, option := range options {
			rr := &dns.PTR{Hdr: rrHeader(name, dns.TypePTR, ttl), Ptr: option.name}
			if err := v.add(rr, false, multiple); err != nil {
				return err
			}
		}
	}
	return nil
}
