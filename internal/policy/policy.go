// Package policy selects the client policy and evaluates filter and manual rules.
package policy

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
	"github.com/pridkett/marco/internal/filter"
	"github.com/pridkett/marco/internal/inventory"
)

const SourceMaxAge = inventory.SourceMaxAge

type manual struct {
	index filter.Index
	refs  map[ruleKey]string
}

type ruleKey struct {
	name   string
	suffix bool
	allow  bool
}

type binding struct {
	id         string
	at         time.Time
	valid      time.Time
	conflicted bool
}

type feed struct {
	digest     string
	allowlist  bool
	allowEmpty bool
	count      int
	index      filter.Index
}

type Engine struct {
	defaultPolicy config.Policy
	defaultFeeds  []string
	groups        map[string]config.Policy
	devices       map[string]config.DeviceSettings
	linked        map[string]string
	bindings      map[netip.Addr][]binding
	reassigned    map[netip.Addr]map[string]bool
	static        map[netip.Addr]config.Assignment
	subnets       []config.Assignment
	assignments   map[string]manual
	globalRules   manual
	groupRules    map[string]manual
	deviceRules   map[string]manual
	services      map[string]filter.Index
	feeds         map[string]feed
}

func Compile(state *config.State, previous *Engine) (*Engine, error) {
	c := state.Desired
	e := &Engine{
		defaultPolicy: c.Default,
		groups:        c.Groups,
		devices:       c.Devices,
		reassigned:    make(map[netip.Addr]map[string]bool),
		bindings:      make(map[netip.Addr][]binding),
		static:        make(map[netip.Addr]config.Assignment),
		assignments:   make(map[string]manual),
		groupRules:    make(map[string]manual),
		deviceRules:   make(map[string]manual),
		services:      make(map[string]filter.Index),
		feeds:         make(map[string]feed),
	}
	var err error
	if e.globalRules, err = compileManual("global", c.Default.Rules); err != nil {
		return nil, err
	}
	for _, name := range slices.Sorted(maps.Keys(c.Groups)) {
		e.groupRules[name], err = compileManual("group/"+name, c.Groups[name].Rules)
		if err != nil {
			return nil, err
		}
	}
	e.linked, err = inventory.LinkTargets(state)
	if err != nil {
		return nil, err
	}
	for _, id := range slices.Sorted(maps.Keys(c.Devices)) {
		device := c.Devices[id]
		e.deviceRules[id], err = compileManual("device/"+id, device.Policy.Rules)
		if err != nil {
			return nil, err
		}
	}
	for _, a := range c.Assignments {
		key := a.Prefix.String()
		e.assignments[key], err = compileManual("assignment/"+key, a.Policy.Rules)
		if err != nil {
			return nil, err
		}
		if a.Prefix.IsSingleIP() {
			e.static[a.Prefix.Addr().Unmap()] = a
		} else {
			e.subnets = append(e.subnets, a)
		}
	}
	slices.SortFunc(e.subnets, func(a, b config.Assignment) int { return b.Prefix.Bits() - a.Prefix.Bits() })
	for id, device := range state.Devices {
		for _, addr := range device.Addresses {
			ip := addr.IP.Unmap()
			if addr.Reassigned {
				if e.reassigned[ip] == nil {
					e.reassigned[ip] = make(map[string]bool)
				}
				e.reassigned[ip][e.identity(id)] = true
			}
			if !device.Connected || device.Legacy || device.LastPoll.IsZero() ||
				!addr.Active || addr.Superseded || addr.LastSeen.IsZero() {
				continue
			}
			at := addr.LastSeen
			if device.LastPoll.Before(at) {
				at = device.LastPoll
			}
			e.bindings[ip] = append(e.bindings[ip], binding{id: id, at: at, valid: at.Add(SourceMaxAge), conflicted: addr.Conflicted})
		}
	}
	for _, name := range slices.Sorted(maps.Keys(c.Services)) {
		service := c.Services[name]
		index := make(filter.Index)
		for _, rule := range service.Domains {
			if rule.Allow {
				return nil, fmt.Errorf("service %q contains an allow rule", name)
			}
			if err := index.Add(rule); err != nil {
				return nil, fmt.Errorf("service %q: %w", name, err)
			}
		}
		e.services[name] = index
	}
	indexRules := 0
	for _, name := range slices.Sorted(maps.Keys(c.Subscriptions)) {
		source := c.Subscriptions[name]
		artifact, have := state.Artifacts[name]
		if !have || !source.Enabled {
			continue
		}
		var old feed
		if previous != nil {
			old = previous.feeds[name]
		}
		if old.digest != artifact.Digest || old.allowlist != artifact.Source.Allowlist ||
			old.allowEmpty != artifact.Source.AllowEmpty || old.index == nil {
			index, count, err := filter.Parse(artifact.Body, artifact.Source.Allowlist, artifact.Source.AllowEmpty)
			if err != nil {
				return nil, fmt.Errorf("subscription %q: %w", name, err)
			}
			old = feed{artifact.Digest, artifact.Source.Allowlist, artifact.Source.AllowEmpty, count, index}
		}
		indexRules += len(old.index)
		if indexRules > filter.MaxIndexRules {
			return nil, fmt.Errorf("subscription indexes exceed the total budget of %d domains", filter.MaxIndexRules)
		}
		artifact.RuleCount = old.count
		state.Artifacts[name] = artifact
		e.feeds[name] = old
		e.defaultFeeds = append(e.defaultFeeds, name)
	}
	return e, nil
}

func compileManual(scope string, rules []config.Rule) (manual, error) {
	if len(rules) == 0 {
		return manual{}, nil
	}
	m := manual{make(filter.Index), make(map[ruleKey]string)}
	for _, r := range rules {
		name, err := config.Name(r.Name)
		if err != nil {
			return manual{}, fmt.Errorf("%s: %w", scope, err)
		}
		key := ruleKey{name, r.Suffix, r.Allow}
		ref := r.ID
		if ref == "" {
			ref = scope + "/" + name
		}
		if _, ok := m.refs[key]; !ok {
			m.refs[key] = ref
		}
		_ = m.index.Add(r)
	}
	return m, nil
}

func (e *Engine) managedDevice(id string) (string, config.DeviceSettings, bool) {
	if d, ok := e.devices[id]; ok && hasPolicy(d) {
		return id, d, true
	}
	if id, ok := e.linked[id]; ok {
		d := e.devices[id]
		return id, d, hasPolicy(d)
	}
	return id, config.DeviceSettings{}, false
}

func hasPolicy(d config.DeviceSettings) bool {
	p := d.Policy
	return d.Group != "" || p.Mode != "" || p.Pool != "" || p.Services != nil || p.Subscriptions != nil || len(p.Rules) != 0
}

func (e *Engine) Select(ip netip.Addr, now time.Time) contract.Selection {
	ip = ip.Unmap()
	var current binding
	conflict := false
	for _, b := range e.bindings[ip] {
		if b.valid.Before(now) || b.at.After(now) {
			continue
		}
		if b.conflicted {
			conflict = true
		}
		if current.id == "" {
			current = b
		} else if !e.sameIdentity(current.id, b.id) {
			conflict = true
		} else if current.id != b.id {
			if b.at.After(current.at) {
				current = b
			}
			current.id = e.identity(b.id)
		}
	}
	if current.id != "" && !conflict {
		if id, d, ok := e.managedDevice(current.id); ok {
			return e.selection(id, d.Group, d.Policy, config.Assignment{}, "device", "observed", current.at)
		}
	}
	if a, ok := e.static[ip]; ok && !conflict {
		if current.id == "" && !e.reassigned[ip][e.identity(a.Device)] {
			return e.fromAssignment(a, "static")
		}
		if current.id != "" && a.Device != "" && e.sameIdentity(a.Device, current.id) {
			return withObservation(e.fromAssignment(a, "static"), current, false)
		}
	}
	for _, a := range e.subnets {
		if a.Prefix.Contains(ip) {
			s := e.fromAssignment(a, "subnet")
			return withObservation(s, current, conflict)
		}
	}
	s := e.selection("", "", config.Policy{}, config.Assignment{}, "default", "unassigned", time.Time{})
	return withObservation(s, current, conflict)
}

func withObservation(s contract.Selection, b binding, conflict bool) contract.Selection {
	if conflict {
		s.Confidence = "conflicting"
	} else if b.id != "" {
		if s.Device == "" {
			s.Device = b.id
		}
		s.Confidence, s.Seen = "observed", b.at
	}
	return s
}

func (e *Engine) identity(id string) string {
	if root := e.linked[id]; root != "" {
		return root
	}
	return id
}

func (e *Engine) sameIdentity(a, b string) bool { return e.identity(a) == e.identity(b) }

func (e *Engine) fromAssignment(a config.Assignment, precedence string) contract.Selection {
	id, d, _ := e.managedDevice(a.Device)
	group := a.Group
	if d.Group != "" {
		group = d.Group
	}
	return e.selection(id, group, d.Policy, a, precedence, "configured", time.Time{})
}

func (e *Engine) selection(id, group string, device config.Policy, a config.Assignment, precedence, confidence string, seen time.Time) contract.Selection {
	p := config.Policy{Mode: config.Filtered}
	inherit(&p, e.defaultPolicy)
	inherit(&p, e.groups[group])
	inherit(&p, a.Policy)
	inherit(&p, device)
	var assignment string
	if a.Prefix.IsValid() {
		assignment = a.Prefix.String()
	}
	return contract.Selection{Device: id, Group: group, Policy: p, Precedence: precedence, Confidence: confidence, Seen: seen, Assignment: assignment}
}

func inherit(base *config.Policy, override config.Policy) {
	if override.Mode != "" {
		base.Mode = override.Mode
	}
	if override.Pool != "" {
		base.Pool = override.Pool
	}
	if override.Services != nil {
		base.Services = override.Services
	}
	if override.Subscriptions != nil {
		base.Subscriptions = override.Subscriptions
	}
}

func (e *Engine) Manual(s contract.Selection, name string) contract.Decision {
	for _, m := range [...]manual{e.deviceRules[s.Device], e.assignments[s.Assignment], e.groupRules[s.Group], e.globalRules} {
		if winning := m.index.Match(name, false); winning.Found {
			reason := "manual-deny"
			if winning.Allow {
				reason = "manual-allow"
			}
			return contract.Decision{Blocked: !winning.Allow, Allowed: winning.Allow, Reason: reason,
				Rule: m.refs[ruleKey{winning.Name, !winning.Exact, winning.Allow}]}
		}
	}
	return contract.Decision{}
}

func (e *Engine) External(s contract.Selection, name string, _ time.Time) contract.Decision {
	if s.Policy.Mode != config.Filtered {
		return contract.Decision{}
	}
	if s.Policy.Services != nil {
		for _, id := range *s.Policy.Services {
			if match := e.services[id].Match(name, false); match.Found {
				return contract.Decision{Blocked: true, Reason: "service-block", Rule: id + "/" + match.Name}
			}
		}
	}
	selected := e.defaultFeeds
	if s.Policy.Subscriptions != nil {
		selected = *s.Policy.Subscriptions
	}
	var best filter.Match
	source := ""
	for _, id := range selected {
		if match := e.feeds[id].index.Match(name, true); match.Wins(best, true) {
			best, source = match, id
		}
	}
	if !best.Found {
		return contract.Decision{}
	}
	reference := source + "/" + best.Name
	if best.Allow {
		return contract.Decision{Allowed: true, Reason: "subscription-allow", Rule: reference}
	}
	return contract.Decision{Blocked: true, Reason: "subscription-block", Rule: reference}
}

func Validate(c config.Desired) error {
	check := func(location string, p config.Policy) error {
		switch p.Mode {
		case "", config.Filtered, config.Unfiltered, config.LocalOnly, config.DenyAll:
		default:
			return fmt.Errorf("%s: unknown mode %q", location, p.Mode)
		}
		if p.Pool != "" && len(c.Pools[p.Pool]) == 0 {
			return fmt.Errorf("%s: upstream pool %q is missing or empty", location, p.Pool)
		}
		if p.Services != nil {
			for _, id := range *p.Services {
				if _, ok := c.Services[id]; !ok {
					return fmt.Errorf("%s: no service %q", location, id)
				}
			}
		}
		if p.Subscriptions != nil {
			for _, id := range *p.Subscriptions {
				if _, ok := c.Subscriptions[id]; !ok {
					return fmt.Errorf("%s: no subscription %q", location, id)
				}
			}
		}
		return nil
	}
	if err := check("default", c.Default); err != nil {
		return err
	}
	for id, p := range c.Groups {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("empty group name")
		}
		if err := check("group "+id, p); err != nil {
			return err
		}
	}
	for id, d := range c.Devices {
		if id == "" {
			return fmt.Errorf("empty device identifier")
		}
		if _, known := c.Groups[d.Group]; d.Group != "" && !known {
			return fmt.Errorf("device %q: unknown group %q", id, d.Group)
		}
		if err := check("device "+id, d.Policy); err != nil {
			return err
		}
	}
	assigned := map[netip.Prefix]bool{}
	for i, a := range c.Assignments {
		if !a.Prefix.IsValid() || a.Prefix != a.Prefix.Masked() || a.Prefix.Addr().Is4In6() {
			return fmt.Errorf("assignment %d: expected a canonical IPv4 or IPv6 prefix", i+1)
		}
		if assigned[a.Prefix] {
			return fmt.Errorf("assignment %d: ambiguous duplicate prefix %s", i+1, a.Prefix)
		}
		assigned[a.Prefix] = true
		if _, known := c.Groups[a.Group]; a.Group != "" && !known {
			return fmt.Errorf("assignment %s: unknown group %q", a.Prefix, a.Group)
		}
		if err := check("assignment "+a.Prefix.String(), a.Policy); err != nil {
			return err
		}
	}
	if len(c.Subscriptions) > 128 {
		return fmt.Errorf("configure at most 128 subscriptions")
	}
	for id, source := range c.Subscriptions {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("empty subscription ID")
		}
		if err := filter.ValidateSource(source); err != nil {
			return fmt.Errorf("subscription %q: %w", id, err)
		}
	}
	for id, svc := range c.Services {
		if strings.TrimSpace(id) == "" || strings.TrimSpace(svc.Version) == "" || len(svc.Domains) == 0 {
			return fmt.Errorf("service %q needs an ID, version and domains", id)
		}
	}
	return nil
}
