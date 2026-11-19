package migrate

import (
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"

	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/filter"
	"go.yaml.in/yaml/v3"
)

type guardSubscription struct {
	ID      int64  `yaml:"id"`
	URL     string `yaml:"url"`
	Enabled bool   `yaml:"enabled"`
}

type guardServices struct {
	IDs      []string  `yaml:"ids"`
	Schedule yaml.Node `yaml:"schedule"`
}

func (s *guardServices) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.SequenceNode {
		return node.Decode(&s.IDs)
	}
	type mapping guardServices
	return node.Decode((*mapping)(s))
}

type guardFiltering struct {
	ProtectionEnabled *bool         `yaml:"protection_enabled"`
	FilteringEnabled  *bool         `yaml:"filtering_enabled"`
	Blocked           guardServices `yaml:"blocked_services"`
	BlockingMode      string        `yaml:"blocking_mode"`
	Rewrites          []yaml.Node   `yaml:"rewrites"`
	Parental          bool          `yaml:"parental_enabled"`
	SafeBrowsing      bool          `yaml:"safebrowsing_enabled"`
	SafeSearch        yaml.Node     `yaml:"safe_search"`
}

type guardClient struct {
	Name            string        `yaml:"name"`
	IDs             []string      `yaml:"ids"`
	UseGlobal       *bool         `yaml:"use_global_settings"`
	Filtering       *bool         `yaml:"filtering_enabled"`
	UseGlobalBlocks *bool         `yaml:"use_global_blocked_services"`
	Blocked         guardServices `yaml:"blocked_services"`
	Upstreams       []string      `yaml:"upstreams"`
	Parental        bool          `yaml:"parental_enabled"`
	SafeBrowsing    bool          `yaml:"safebrowsing_enabled"`
	SafeSearch      yaml.Node     `yaml:"safe_search"`
	IgnoreLog       bool          `yaml:"ignore_querylog"`
	IgnoreStats     bool          `yaml:"ignore_statistics"`
}

type guardClients struct {
	Persistent []guardClient `yaml:"persistent"`
}

func (c *guardClients) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.SequenceNode {
		return node.Decode(&c.Persistent)
	}
	type mapping guardClients
	return node.Decode((*mapping)(c))
}

type guardConfig struct {
	Filters   []guardSubscription `yaml:"filters"`
	Whitelist []guardSubscription `yaml:"whitelist_filters"`
	Rules     []string            `yaml:"user_rules"`
	Filtering guardFiltering      `yaml:"filtering"`
	Clients   guardClients        `yaml:"clients"`
	DNS       struct {
		guardFiltering `yaml:",inline"`
		Upstreams      []string `yaml:"upstream_dns"`
		UpstreamFile   string   `yaml:"upstream_dns_file"`
		DNS64          bool     `yaml:"use_dns64"`
	} `yaml:"dns"`
	TLS struct {
		Enabled bool   `yaml:"enabled"`
		HTTPS   uint16 `yaml:"port_https"`
		DoT     uint16 `yaml:"port_dns_over_tls"`
		DoQ     uint16 `yaml:"port_dns_over_quic"`
		DoH     bool   `yaml:"allow_unencrypted_doh"`
	} `yaml:"tls"`
	DNSCrypt struct {
		Enabled bool   `yaml:"enabled"`
		Port    uint16 `yaml:"port"`
	} `yaml:"dnscrypt"`
}

func (p *importer) adGuard() error {
	if p.options.AdGuardPath == "" {
		return nil
	}
	file, err := readLegacy(p.options.AdGuardPath)
	if err != nil {
		return err
	}
	var ag guardConfig
	if err := yaml.Unmarshal(file, &ag); err != nil {
		// YAML type errors can include input values, which are not needed in a preview.
		return fmt.Errorf("cannot decode sanitized AdGuard YAML")
	}
	p.guardSubscriptions(ag.Filters, false)
	p.guardSubscriptions(ag.Whitelist, true)
	global := ag.Filtering
	legacy := ag.DNS.guardFiltering
	if global.ProtectionEnabled == nil {
		global.ProtectionEnabled = legacy.ProtectionEnabled
	}
	if global.FilteringEnabled == nil {
		global.FilteringEnabled = legacy.FilteringEnabled
	}
	if global.Blocked.IDs == nil {
		global.Blocked = legacy.Blocked
	}
	if global.BlockingMode == "" {
		global.BlockingMode = legacy.BlockingMode
	}
	if len(global.Rewrites)+len(legacy.Rewrites) != 0 {
		p.unsupported("AdGuard filtering.rewrites", "DNS rewrites need explicit conversion to local records")
	}
	if global.BlockingMode != "" && global.BlockingMode != "nxdomain" {
		p.unsupported("AdGuard filtering.blocking_mode", "Marco uses NXDOMAIN for domain blocks")
	}
	if global.Parental || legacy.Parental || global.SafeBrowsing || legacy.SafeBrowsing || nodeEnabled(global.SafeSearch) || nodeEnabled(legacy.SafeSearch) {
		p.unsupported("AdGuard protection", "built-in parental control, safe browsing or safe search")
	}
	if ag.TLS.Enabled || ag.TLS.HTTPS != 0 || ag.TLS.DoT != 0 || ag.TLS.DoQ != 0 || ag.TLS.DoH {
		p.unsupported("AdGuard tls", "configured encrypted client listener settings require separate deployment review")
	}
	if ag.DNSCrypt.Enabled || ag.DNSCrypt.Port != 0 {
		p.unsupported("AdGuard dnscrypt", "configured DNSCrypt listener settings require separate deployment review")
	}
	if ag.DNS.DNS64 {
		p.unsupported("AdGuard dns.use_dns64", "DNS64 synthesis")
	}
	if (len(ag.DNS.Upstreams) != 0 || ag.DNS.UpstreamFile != "") && len(p.options.Disposition.Upstreams) == 0 && p.options.DesiredPath == "" {
		p.unsupported("AdGuard dns.upstream_dns", "supply reviewed encrypted endpoints as versioned pools")
	}
	protectionOff := global.ProtectionEnabled != nil && !*global.ProtectionEnabled
	if protectionOff || global.FilteringEnabled != nil && !*global.FilteringEnabled {
		p.guardGlobalSelection("AdGuard filtering", &p.Desired.Default.Subscriptions, []string{})
	}
	if services := p.guardServices("AdGuard filtering.blocked_services", global.Blocked); protectionOff {
		p.guardGlobalSelection("AdGuard protection", &p.Desired.Default.Services, []string{})
	} else if services != nil {
		p.guardGlobalSelection("AdGuard blocked services", &p.Desired.Default.Services, *services)
	}
	seen := make(map[string]bool)
	for _, rule := range p.Desired.Default.Rules {
		seen[rule.ID] = true
	}
	for i, line := range ag.Rules {
		loc := fmt.Sprintf("AdGuard user_rules[%d]", i)
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
			continue
		}
		r, err := filter.ParseRule(line)
		if err != nil {
			subtype := "unsupported custom rule"
			switch {
			case strings.Contains(line, "$dnsrewrite"):
				subtype = "DNS rewrite"
			case strings.Contains(line, "$client"):
				subtype = "client-specific rule"
			case strings.Contains(line, "$"):
				subtype = "rule modifier"
			case strings.HasPrefix(line, "/") || strings.HasPrefix(line, "@@/"):
				subtype = "regular expression"
			}
			p.unsupported(loc, subtype)
			continue
		}
		if protectionOff {
			p.exclude(loc, "custom filtering was disabled by global protection settings")
			continue
		}
		r.ID = fmt.Sprintf("adguard-rule/%d", i+1)
		for _, old := range p.Desired.Default.Rules {
			if old.Allow == r.Allow && old.Suffix == r.Suffix && keyName(old.Name) == r.Name {
				seen[r.ID] = true
			}
		}
		if !seen[r.ID] {
			p.Desired.Default.Rules = append(p.Desired.Default.Rules, r)
			p.accept(loc, "manual rule "+r.Name)
		} else if slices.ContainsFunc(p.Desired.Default.Rules, func(old config.Rule) bool { return old.ID == r.ID && old != r }) {
			p.conflict(loc, "kept existing manual rule")
		}
	}
	for i, c := range ag.Clients.Persistent {
		p.guardClient(fmt.Sprintf("AdGuard clients.persistent[%d]", i), c)
	}
	return nil
}

func nodeEnabled(node yaml.Node) bool {
	if node.Kind == yaml.ScalarNode {
		return node.Value == "true"
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == "enabled" {
			return node.Content[i+1].Value == "true"
		}
	}
	return false
}

func (p *importer) guardGlobalSelection(loc string, target **[]string, selection []string) {
	if *target == nil {
		*target = &selection
		p.accept(loc, "applied explicit global selection")
	} else if !slices.Equal(**target, selection) {
		p.conflict(loc, "kept existing global selection")
	}
}

func (p *importer) guardSubscriptions(entries []guardSubscription, allow bool) {
	kind := "filters"
	if allow {
		kind = "whitelist_filters"
	}
	for i, entry := range entries {
		loc := fmt.Sprintf("AdGuard %s[%d]", kind, i)
		id := fmt.Sprintf("adguard-%s-%d", kind, entry.ID)
		if entry.ID == 0 {
			id = fmt.Sprintf("adguard-%s-row-%d", kind, i+1)
		}
		source := config.Subscription{URL: entry.URL, Enabled: entry.Enabled, Allowlist: allow}
		if err := filter.ValidateSource(source); err != nil {
			p.unsupported(loc, "source requires an HTTPS URL or explicit provisioned file mapping")
			continue
		}
		if existing, exists := p.Desired.Subscriptions[id]; exists {
			if existing != source {
				p.conflict(loc, "kept existing subscription "+id)
			}
			continue
		}
		if p.Desired.Subscriptions == nil {
			p.Desired.Subscriptions = map[string]config.Subscription{}
		}
		p.Desired.Subscriptions[id] = source
		p.accept(loc, "registered subscription "+id)
	}
}

func (p *importer) guardServices(loc string, source guardServices) *[]string {
	if source.Schedule.Kind != 0 && source.Schedule.Kind != yaml.ScalarNode && len(source.Schedule.Content) != 0 {
		p.unsupported(loc+".schedule", "review schedule before applying service blocks all day")
	}
	if source.IDs == nil {
		return nil
	}
	names := make([]string, 0, len(source.IDs))
	for _, id := range source.IDs {
		_, exists := p.Desired.Services[id]
		if !exists {
			service, ok := p.options.Disposition.Services[id]
			if !ok {
				p.unsupported(loc, "unmapped service "+id)
				continue
			}
			if p.Desired.Services == nil {
				p.Desired.Services = map[string]config.Service{}
			}
			p.Desired.Services[id] = service
			p.accept(loc, "mapped custom service "+id)
		}
		if !slices.Contains(names, id) {
			names = append(names, id)
		}
	}
	return &names
}

func (p *importer) guardClient(loc string, c guardClient) {
	if strings.TrimSpace(c.Name) == "" {
		p.unsupported(loc, "unnamed persistent client")
		return
	}
	policy := config.Policy{}
	if (c.UseGlobal == nil || !*c.UseGlobal) && c.Filtering != nil {
		if !*c.Filtering {
			empty := []string{}
			policy.Subscriptions = &empty
		} else if p.Desired.Default.Subscriptions != nil {
			// Re-enable the imported selection for clients that had their own
			// filtering setting when AdGuard's global selection was disabled.
			selected := make([]string, 0)
			for _, id := range slices.Sorted(maps.Keys(p.Desired.Subscriptions)) {
				if strings.HasPrefix(id, "adguard-filters-") || strings.HasPrefix(id, "adguard-whitelist_filters-") {
					selected = append(selected, id)
				}
			}
			policy.Subscriptions = &selected
		}
	}
	if c.UseGlobalBlocks == nil || !*c.UseGlobalBlocks {
		policy.Services = p.guardServices(loc+".blocked_services", c.Blocked)
		if c.UseGlobalBlocks != nil && policy.Services == nil {
			empty := []string{}
			policy.Services = &empty
		}
	}
	if len(c.Upstreams) != 0 || c.Parental || c.SafeBrowsing || nodeEnabled(c.SafeSearch) || c.IgnoreLog || c.IgnoreStats {
		p.unsupported(loc, "client has separate upstream, protection or privacy settings requiring operator review")
	}
	group := "adguard/" + c.Name
	if existing, exists := p.Desired.Groups[group]; exists {
		if !reflect.DeepEqual(existing, policy) {
			p.conflict(loc, "kept existing group "+group)
		}
	} else {
		if p.Desired.Groups == nil {
			p.Desired.Groups = map[string]config.Policy{}
		}
		p.Desired.Groups[group] = policy
		p.accept(loc, "client group "+group)
	}
	if len(c.IDs) == 0 {
		p.unsupported(loc+".ids", "persistent client has no selectors")
	}
	for i, selector := range c.IDs {
		where := fmt.Sprintf("%s.ids[%d]", loc, i)
		if id := selectorDevice(p.State, p.options.Disposition.Selectors, selector); id != "" {
			d := p.Desired.Devices[id]
			if d.Group != "" && d.Group != group {
				p.conflict(where, "kept existing device group for "+id)
			} else if d.Group == "" {
				d.Group = group
				if p.Desired.Devices == nil {
					p.Desired.Devices = map[string]config.DeviceSettings{}
				}
				p.Desired.Devices[id] = d
				p.accept(where, "assigned device "+id)
			}
			continue
		}
		prefix, err := netip.ParsePrefix(selector)
		if err != nil {
			addr, ipErr := netip.ParseAddr(selector)
			if ipErr != nil || addr.Zone() != "" {
				p.unsupported(where, "unresolved client selector")
				continue
			}
			addr = addr.Unmap()
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		prefix = prefix.Masked()
		at := slices.IndexFunc(p.Desired.Assignments, func(a config.Assignment) bool { return a.Prefix == prefix })
		if at == -1 {
			p.Desired.Assignments = append(p.Desired.Assignments, config.Assignment{Prefix: prefix, Group: group})
			p.accept(where, "assigned "+prefix.String())
		} else if p.Desired.Assignments[at].Group != group {
			p.conflict(where, "kept existing assignment for "+prefix.String())
		}
	}
}
