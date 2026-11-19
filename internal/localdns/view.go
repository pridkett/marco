// Package localdns compiles manual and learned DNS records into an immutable view.
package localdns

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
	"github.com/pridkett/marco/internal/inventory"
)

const maxAliasDepth = 16

type Issue struct {
	Kind    string     `json:"kind"`
	Name    string     `json:"name,omitempty"`
	Device  string     `json:"device,omitempty"`
	Address netip.Addr `json:"address,omitzero"`
	Detail  string     `json:"detail,omitempty"`
}

type zone struct {
	name    string
	private bool
	soa     *dns.SOA
}

type owner struct {
	sets   map[uint16][]dns.RR
	public bool
}

type View struct {
	owners     map[string]*owner
	hidden     map[string]bool
	empty      map[string]bool
	published  map[string]bool
	zones      []zone
	reverse    []netip.Prefix
	issues     []Issue
	revision   uint32
	staticTTL  uint32
	dynamicTTL uint32
}

func Compile(state *config.State) (*View, error) {
	if err := inventory.Prepare(state); err != nil {
		return nil, err
	}
	v := &View{
		owners: make(map[string]*owner), hidden: make(map[string]bool), empty: make(map[string]bool),
		published: make(map[string]bool),
		revision:  uint32(state.Revision), staticTTL: state.Desired.StaticTTL, dynamicTTL: state.Desired.DynamicTTL,
	}
	if v.staticTTL == 0 {
		v.staticTTL = 300
	}
	if v.dynamicTTL == 0 {
		v.dynamicTTL = 60
	}
	var publication []string
	seenZones := make(map[string]bool)
	for i, spec := range state.Desired.Zones {
		name, err := config.Name(spec.Name)
		if err != nil {
			return nil, fmt.Errorf("zones[%d]: %w", i, err)
		}
		if seenZones[name] {
			return nil, fmt.Errorf("duplicate zone %s", name)
		}
		seenZones[name] = true
		z := zone{name: name, private: spec.Private, soa: v.soa(name)}
		v.zones = append(v.zones, z)
		if spec.Publish {
			if len(name)+64 > 254 {
				return nil, fmt.Errorf("publication suffix %s leaves no room for a full device label", name)
			}
			publication = append(publication, name)
		}
	}
	slices.SortFunc(v.zones, func(a, b zone) int { return len(b.name) - len(a.name) })

	seenReverse := make(map[netip.Prefix]bool)
	for i, prefix := range state.Desired.Reverse {
		if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" || prefix != prefix.Masked() {
			return nil, fmt.Errorf("reverse[%d]: invalid canonical LAN prefix %s", i, prefix)
		}
		if seenReverse[prefix] {
			return nil, fmt.Errorf("duplicate LAN reverse prefix %s", prefix)
		}
		seenReverse[prefix] = true
		v.reverse = append(v.reverse, prefix)
	}
	slices.SortFunc(v.reverse, func(a, b netip.Prefix) int { return b.Bits() - a.Bits() })

	for i, spec := range state.Desired.Records {
		rr, err := v.record(spec)
		if err == nil {
			err = v.add(rr, spec.Public, state.Desired.MultiplePTRs)
		}
		if err != nil {
			return nil, fmt.Errorf("records[%d]: %w", i, err)
		}
	}
	for _, z := range v.zones {
		if z.private {
			if err := v.add(z.soa, false, true); err != nil {
				return nil, fmt.Errorf("zone %s: %w", z.name, err)
			}
		}
	}

	if err := v.publish(state, publication); err != nil {
		return nil, err
	}
	for name := range v.owners {
		for ancestor := parentName(name); ancestor != ""; ancestor = parentName(ancestor) {
			if v.privateZone(ancestor) != nil || v.reverseZone(ancestor) != "" {
				v.empty[ancestor] = true
			}
		}
	}
	if err := v.validateAliases(); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *View) Issues() []Issue {
	return slices.Clone(v.issues)
}

func (v *View) Published(deviceID string) bool {
	return v.published[deviceID]
}

func within(name, suffix string) bool {
	return name == suffix || strings.HasSuffix(name, "."+suffix)
}

func parentName(name string) string {
	i := strings.IndexByte(name, '.')
	if i < 0 {
		return ""
	}
	return name[i+1:]
}

func (v *View) configuredZone(name string) *zone {
	for i := range v.zones {
		if within(name, v.zones[i].name) {
			return &v.zones[i]
		}
	}
	return nil
}

func (v *View) privateZone(name string) *zone {
	for i := range v.zones {
		if v.zones[i].private && within(name, v.zones[i].name) {
			return &v.zones[i]
		}
	}
	return nil
}

func (v *View) soa(name string) *dns.SOA {
	adminName, dnsName := "hostmaster.", "marco."
	if name != "." {
		if candidate, err := config.Name("hostmaster." + name); err == nil {
			adminName = candidate
		}
		if candidate, err := config.Name("marco." + name); err == nil {
			dnsName = candidate
		}
	}
	return &dns.SOA{
		Hdr: rrHeader(name, dns.TypeSOA, v.staticTTL), Ns: dnsName, Mbox: adminName,
		Serial: v.revision, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: v.staticTTL,
	}
}

func (v *View) negativeSOA(name, fallback string) *dns.SOA {
	if z := v.privateZone(name); z != nil {
		return z.soa
	}
	if reverse := v.reverseZone(name); reverse != "" {
		return v.soa(reverse)
	}
	if z := v.configuredZone(name); z != nil {
		return z.soa
	}
	if fallback == "" {
		fallback = parentName(name)
	}
	if fallback == "" {
		fallback = "."
	}
	return v.soa(fallback)
}

func (v *View) publicTarget(name string, explicit bool) bool {
	if v.owners[name] != nil || v.hidden[name] || v.empty[name] ||
		v.privateZone(name) != nil || v.reverseZone(name) != "" {
		return false
	}
	return explicit || (parentName(name) != "" && v.configuredZone(name) == nil)
}

func (v *View) validateAliases() error {
	// The functional graph has at most one edge per alias. Walk each link once
	// to validate cycles without growing a call stack with the configuration.
	type terminal struct {
		missing string
	}
	resolved := make(map[string]terminal)
	for _, name := range slices.Sorted(maps.Keys(v.owners)) {
		if len(v.owners[name].sets[dns.TypeCNAME]) == 0 {
			continue
		}
		path := make(map[string]bool)
		var traversed []string
		next := name
		var result terminal
		for {
			if prior, ok := resolved[next]; ok {
				result = prior
				break
			}
			if path[next] {
				return fmt.Errorf("local CNAME cycle includes %s", next)
			}
			entry := v.owners[next]
			// A non-alias owner is a valid terminal even when a later DNS query
			// selects a type that does not exist there.
			if entry != nil && len(entry.sets[dns.TypeCNAME]) == 0 {
				break
			}
			path[next] = true
			traversed = append(traversed, next)
			target := entry.sets[dns.TypeCNAME][0].(*dns.CNAME).Target
			if v.publicTarget(target, entry.public) {
				break
			}
			if v.owners[target] == nil {
				if !v.empty[target] {
					result.missing = target
				}
				break
			}
			next = target
		}
		for _, alias := range traversed {
			resolved[alias] = result
		}
	}
	for _, name := range slices.Sorted(maps.Keys(resolved)) {
		if deadEnd := resolved[name].missing; deadEnd != "" {
			v.issues = append(v.issues, Issue{Kind: "unresolved-alias", Name: name, Detail: deadEnd})
		}
	}
	return nil
}

func (v *View) Lookup(name string, qtype uint16) contract.LocalResult {
	result := contract.LocalResult{Found: true, Code: dns.RcodeSuccess, Authoritative: true}
	current, fallback := name, ""
	for depth := 0; depth <= maxAliasDepth; depth++ {
		entry := v.owners[current]
		if entry != nil {
			if qtype == dns.TypeANY {
				for _, rtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypePTR, dns.TypeSOA} {
					result.Answer = append(result.Answer, entry.sets[rtype]...)
				}
				return result
			}
			if rrset := entry.sets[qtype]; len(rrset) != 0 {
				result.Answer = append(result.Answer, rrset...)
				return result
			}
			if link := entry.sets[dns.TypeCNAME]; len(link) != 0 {
				if depth == maxAliasDepth {
					return contract.LocalResult{Found: true, Code: dns.RcodeServerFailure}
				}
				target := link[0].(*dns.CNAME).Target
				result.Answer = append(result.Answer, link[0])
				if v.publicTarget(target, entry.public) {
					result.PublicTarget, result.Authoritative = target, false
					return result
				}
				current, fallback = target, parentName(current)
				continue
			}
			result.Authority = []dns.RR{v.negativeSOA(current, fallback)}
			return result
		}
		if v.hidden[current] {
			result.Suppressed = true
			result.Code = dns.RcodeNameError
		} else if reverse := v.reverseZone(current); reverse != "" {
			// A complete host address is absent unless it has a published PTR.
			// Partial reverse names at the authority's apex can answer SOA.
			if _, full := reversePrefix(current); !full && current == reverse {
				if qtype == dns.TypeSOA || qtype == dns.TypeANY {
					result.Answer = append(result.Answer, v.soa(reverse))
					return result
				}
			} else if !v.empty[current] {
				result.Code = dns.RcodeNameError
			}
		} else if v.empty[current] {
			result.Code = dns.RcodeSuccess
		} else if v.privateZone(current) != nil || depth > 0 {
			result.Code = dns.RcodeNameError
		} else {
			return contract.LocalResult{}
		}
		result.Authority = []dns.RR{v.negativeSOA(current, fallback)}
		return result
	}
	return contract.LocalResult{Found: true, Code: dns.RcodeServerFailure}
}
