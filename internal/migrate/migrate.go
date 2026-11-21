// Package migrate previews offline imports into a candidate for the normal publisher.
package migrate

import (
	"crypto/sha256"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/pridkett/marco/internal/config"
)

type Options struct {
	DesiredPath, StatePath, ScraperPath, PowerDNSPath, AdGuardPath string
	Disposition                                                    Disposition
	ReplaceDesired                                                 bool
	BuiltInServices                                                map[string]config.Service
}

type Disposition struct {
	AddressRows string                       `json:"addressRows,omitempty"`
	RowChoices  map[string]string            `json:"rowChoices,omitempty"`
	Retired     []string                     `json:"retiredAliases,omitempty"`
	Services    map[string]config.Service    `json:"services,omitempty"`
	Selectors   map[string]string            `json:"deviceSelectors,omitempty"`
	Upstreams   map[string][]config.Endpoint `json:"upstreamPools,omitempty"`
	DefaultPool string                       `json:"defaultPool,omitempty"`
	Reverse     []netip.Prefix               `json:"reverse,omitempty"`
}

type InventoryState struct {
	Version   int                      `json:"version"`
	Devices   map[string]config.Device `json:"devices"`
	SitePolls map[string]time.Time     `json:"sitePolls,omitempty"`
}

type Item struct {
	Source string `json:"source"`
	Detail string `json:"detail"`
}

type Report struct {
	Base        uint64   `json:"baseRevision"`
	Applied     uint64   `json:"appliedRevision,omitempty"`
	Accepted    []Item   `json:"accepted"`
	Exclusions  []Item   `json:"exclusions"`
	Conflicts   []Item   `json:"conflicts"`
	Unsupported []Item   `json:"unsupported"`
	Warnings    []Item   `json:"warnings"`
	Staged      []string `json:"stagedSubscriptions"`
}

type importer struct {
	*config.State
	report  Report
	options Options
	byOwner map[string][]config.Record
	aliases map[string]string
}

func Build(state *config.State, options Options) (Report, error) {
	p := &importer{State: state, options: options, report: Report{Base: state.Generation},
		byOwner: map[string][]config.Record{}, aliases: map[string]string{}}
	if err := p.importAll(); err != nil {
		return p.report, err
	}
	p.report.Staged = Staged(state)
	return p.report, nil
}

func Staged(state *config.State) []string {
	var names []string
	for name, spec := range state.Desired.Subscriptions {
		if spec.Enabled && (state.Artifacts[name].Digest == "" || state.Artifacts[name].Source != spec) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func (p *importer) importAll() error {
	d := &p.Desired
	if o := p.options.DesiredPath; o != "" {
		var settings config.Desired
		if err := config.ReadJSON(o, &settings); err != nil {
			return fmt.Errorf("portable settings: %w", err)
		}
		switch {
		case reflect.DeepEqual(*d, settings):
		case p.options.ReplaceDesired || reflect.DeepEqual(*d, config.Defaults()):
			*d = settings
			p.accept("portable settings", "loaded versioned desired configuration")
		default:
			return fmt.Errorf("existing desired settings differ; explicitly select replacement for a full settings import")
		}
	}
	if o := p.options.StatePath; o != "" {
		var inventory InventoryState
		if err := config.ReadJSON(o, &inventory); err != nil {
			return fmt.Errorf("inventory: %w", err)
		}
		if inventory.Version != config.Version {
			return fmt.Errorf("unsupported inventory version %d", inventory.Version)
		}
		for _, id := range slices.Sorted(maps.Keys(inventory.Devices)) {
			// Import history and publication. The source never becomes a live identity until polled locally.
			dev := inventory.Devices[id]
			dev.Connected = false
			for i := range dev.Addresses {
				dev.Addresses[i].Active = false
			}
			if existing, exists := p.Devices[id]; exists {
				if !reflect.DeepEqual(existing, dev) {
					p.conflict("inventory", "kept existing device "+id)
				}
				continue
			}
			if p.Devices == nil {
				p.Devices = map[string]config.Device{}
			}
			p.Devices[id] = dev
			p.accept("inventory", "imported device "+id)
		}
		// Source freshness is local to this instance. Device history retains absolute poll times.
	}
	for _, r := range d.Records {
		p.index(r)
	}
	for _, network := range p.options.Disposition.Reverse {
		if !slices.Contains(d.Reverse, network) {
			d.Reverse = append(d.Reverse, network)
			p.accept("disposition", "added LAN reverse space "+network.String())
		}
	}
	for _, name := range slices.Sorted(maps.Keys(p.options.Disposition.Upstreams)) {
		endpoints := p.options.Disposition.Upstreams[name]
		if _, exists := d.Pools[name]; exists {
			if !reflect.DeepEqual(d.Pools[name], endpoints) {
				p.conflict("disposition", "kept existing upstream pool "+name)
			}
			continue
		}
		if d.Pools == nil {
			d.Pools = map[string][]config.Endpoint{}
		}
		d.Pools[name] = endpoints
		p.accept("disposition", "added encrypted upstream pool "+name)
	}
	if name := p.options.Disposition.DefaultPool; name != "" && d.Default.Pool != name {
		if d.Default.Pool != "" {
			p.conflict("disposition", "kept existing default upstream pool")
		} else {
			d.Default.Pool = name
		}
	}
	if err := p.scraper(); err != nil {
		return err
	}
	if err := p.powerDNS(); err != nil {
		return err
	}
	return p.adGuard()
}

func (p *importer) accept(source, detail string) {
	p.report.Accepted = append(p.report.Accepted, Item{source, detail})
}

func (p *importer) exclude(source, detail string) {
	p.report.Exclusions = append(p.report.Exclusions, Item{source, detail})
}

func (p *importer) unsupported(source, detail string) {
	p.report.Unsupported = append(p.report.Unsupported, Item{source, detail})
}

func (p *importer) conflict(source, detail string) {
	p.report.Conflicts = append(p.report.Conflicts, Item{source, detail})
}

func (p *importer) warning(source, detail string) {
	p.report.Warnings = append(p.report.Warnings, Item{source, detail})
}

func keyName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".") + "."
}

func (p *importer) index(r config.Record) {
	owner := keyName(r.Name)
	p.byOwner[owner] = append(p.byOwner[owner], r)
	if strings.EqualFold(r.Type, "CNAME") {
		p.aliases[owner] = keyName(r.Value)
	}
}

func (p *importer) record(source string, r config.Record, multi bool) {
	var err error
	r.Name, err = config.Name(r.Name)
	if err != nil {
		p.unsupported(source, err.Error())
		return
	}
	switch r.Type {
	case "A", "AAAA":
		ip, err := netip.ParseAddr(r.Value)
		if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.Is4In6() || ip.Is4() != (r.Type == "A") {
			p.unsupported(source, "invalid record address at "+r.Name)
			return
		}
		r.Value = ip.String()
	case "CNAME", "PTR":
		r.Value, err = config.Name(r.Value)
		if err != nil {
			p.unsupported(source, err.Error())
			return
		}
	default:
		p.unsupported(source, "unsupported record type "+r.Type)
		return
	}
	for _, old := range p.byOwner[r.Name] {
		t := strings.ToUpper(old.Type)
		value := old.Value
		if t == "CNAME" || t == "PTR" {
			value = keyName(value)
		}
		if t == r.Type && value == r.Value {
			return
		}
		if t == "CNAME" || r.Type == "CNAME" || t == r.Type && !multi {
			p.conflict(source, "kept existing record at "+r.Name)
			return
		}
	}
	if r.Type == "CNAME" {
		seen := map[string]bool{r.Name: true}
		for name := r.Value; name != ""; name = p.aliases[name] {
			if seen[name] {
				p.unsupported(source, "CNAME would close a loop at "+r.Name)
				return
			}
			seen[name] = true
		}
	}
	p.Desired.Records = append(p.Desired.Records, r)
	p.index(r)
	p.accept(source, r.Type+" "+r.Name)
}

func (p *importer) legacy(source string, r config.Record) {
	hash := sha256.Sum256([]byte(r.Name))
	id := fmt.Sprintf("legacy-%x", hash[:16])
	ip, err := netip.ParseAddr(r.Value)
	if err != nil || ip.Zone() != "" || ip.Is4In6() || ip.IsUnspecified() || ip.IsMulticast() || ip.Is4() != (r.Type == "A") {
		p.unsupported(source, "invalid legacy address at "+r.Name)
		return
	}
	if p.Devices == nil {
		p.Devices = make(map[string]config.Device)
	}
	device, exists := p.Devices[id]
	if !exists {
		device = config.Device{ID: id, Legacy: true, LegacyOwner: r.Name, Reported: r.Name}
	}
	if !device.Legacy || device.LegacyOwner != r.Name {
		p.conflict(source, "kept existing device for "+r.Name)
		return
	}
	for _, old := range device.Addresses {
		if old.IP == ip {
			return
		}
	}
	device.Addresses = append(device.Addresses, config.Address{IP: ip, Publish: true, Provenance: "legacy"})
	p.Devices[id] = device
	p.accept(source, "legacy observation "+r.Name)
}

func selectorDevice(state *config.State, mapping map[string]string, value string) string {
	if id := mapping[value]; id != "" {
		return id
	}
	if mac, err := net.ParseMAC(value); err == nil {
		var id string
		for found, device := range state.Devices {
			if device.MAC == mac.String() {
				if id != "" {
					return ""
				}
				id = found
			}
		}
		return id
	}
	return ""
}
