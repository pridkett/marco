package migrate

import (
	"database/sql"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/pridkett/marco/internal/config"
	_ "modernc.org/sqlite"
)

type host struct {
	IP        string   `toml:"ip"`
	Name      string   `toml:"name"`
	Hostnames []string `toml:"hostnames"`
}

type scraperConfig struct {
	Processing struct {
		Domains    []string `toml:"domains"`
		Additional []host   `toml:"additional"`
		Blocked    []host   `toml:"blocked"`
		CNames     []struct {
			Alias  string `toml:"cname"`
			Target string `toml:"hostname"`
		} `toml:"cnames"`
		KeepMACs bool `toml:"keep_macs"`
	} `toml:"processing"`
}

func readLegacy(file string) ([]byte, error) {
	info, err := os.Stat(file)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 32<<20 {
		return nil, fmt.Errorf("expected a regular file of at most 32 MiB")
	}
	return os.ReadFile(file)
}

func (p *importer) scraper() error {
	if p.options.ScraperPath == "" {
		return nil
	}
	file, err := readLegacy(p.options.ScraperPath)
	if err != nil {
		return err
	}
	var scraper scraperConfig
	if err := toml.Unmarshal(file, &scraper); err != nil {
		return fmt.Errorf("invalid scraper TOML: %w", err)
	}
	processing := scraper.Processing
	var zones []string
	for i, domain := range processing.Domains {
		loc := fmt.Sprintf("scraper processing.domains[%d]", i)
		name, err := config.Name(domain)
		if err != nil {
			p.unsupported(loc, err.Error())
			continue
		}
		zones = append(zones, name)
		index := slices.IndexFunc(p.Desired.Zones, func(z config.Zone) bool { return keyName(z.Name) == name })
		if index < 0 {
			p.Desired.Zones = append(p.Desired.Zones, config.Zone{Name: name, Publish: true})
			p.accept(loc, "split publication zone "+name)
		} else if !p.Desired.Zones[index].Publish || p.Desired.Zones[index].Private {
			p.conflict(loc, "kept existing zone "+name)
		}
	}
	for i, h := range processing.Additional {
		loc := fmt.Sprintf("scraper processing.additional[%d]", i)
		ip, err := netip.ParseAddr(h.IP)
		if err != nil {
			p.unsupported(loc, "invalid additional host address")
			continue
		}
		recordType := "A"
		if ip.Is6() {
			recordType = "AAAA"
		}
		names := h.Hostnames
		if len(names) == 0 {
			names = []string{h.Name}
		}
		for _, name := range names {
			if !strings.Contains(name, ".") && len(zones) != 0 {
				for _, zone := range zones {
					p.record(loc, config.Record{Name: name + "." + zone, Type: recordType, Value: h.IP}, false)
				}
			} else {
				p.record(loc, config.Record{Name: name, Type: recordType, Value: h.IP}, false)
			}
		}
	}
	for i, rule := range processing.Blocked {
		loc := fmt.Sprintf("scraper processing.blocked[%d]", i)
		s := config.Suppression{Name: rule.Name}
		if rule.Name != "" {
			s.Name, err = config.Name(rule.Name)
			if err != nil {
				p.unsupported(loc, err.Error())
				continue
			}
			if !strings.Contains(strings.TrimSuffix(s.Name, "."), ".") {
				s.Name = strings.TrimSuffix(s.Name, ".")
			}
		}
		if rule.IP != "" {
			s.Address, err = netip.ParseAddr(rule.IP)
			if err != nil {
				p.unsupported(loc, "invalid suppression address")
				continue
			}
		}
		if s.Name == "" && !s.Address.IsValid() {
			p.unsupported(loc, "empty suppression")
		} else if !slices.Contains(p.Desired.Suppressions, s) {
			p.Desired.Suppressions = append(p.Desired.Suppressions, s)
			p.accept(loc, "publication suppression")
		}
	}
	for i, alias := range processing.CNames {
		p.record(fmt.Sprintf("scraper processing.cnames[%d]", i),
			config.Record{Name: alias.Alias, Type: "CNAME", Value: alias.Target}, false)
	}
	if processing.KeepMACs {
		p.unsupported("scraper processing.keep_macs", "MAC-derived names need explicit operator names")
	}
	return nil
}

func (p *importer) powerDNS() error {
	path := p.options.PowerDNSPath
	if path == "" {
		return nil
	}
	retired := make(map[string]bool, len(p.options.Disposition.Retired))
	for _, name := range p.options.Disposition.Retired {
		canonical, err := config.Name(name)
		if err != nil {
			return fmt.Errorf("retired alias: %w", err)
		}
		retired[canonical] = true
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	u := url.URL{Scheme: "file", Path: abs, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT id, coalesce(name,''), upper(coalesce(type,'')), coalesce(content,''), coalesce(ttl,0)
		FROM records WHERE coalesce(disabled,0)=0 ORDER BY id LIMIT 100001`)
	if err != nil {
		return fmt.Errorf("PowerDNS records: %w", err)
	}
	defer rows.Close()
	initial := make(map[string]bool, len(p.byOwner))
	for name := range p.byOwner {
		initial[name] = true
	}
	count := 0
	for rows.Next() {
		count++
		if count > 100000 {
			return fmt.Errorf("PowerDNS backup exceeds 100000 enabled records")
		}
		var id string
		var r config.Record
		if err := rows.Scan(&id, &r.Name, &r.Type, &r.Value, &r.TTL); err != nil {
			return err
		}
		loc := "PowerDNS records/" + id
		name, err := config.Name(r.Name)
		if err != nil {
			p.unsupported(loc, err.Error())
			continue
		}
		r.Name = name
		if r.Type == "CNAME" && retired[name] {
			p.exclude(loc, "retired alias "+name)
			continue
		}
		if initial[name] {
			p.exclude(loc, "kept explicit owner "+name)
			continue
		}
		if r.Type != "A" && r.Type != "AAAA" {
			p.record(loc, r, true)
			continue
		}
		choice := p.options.Disposition.RowChoices[id]
		if choice == "" {
			choice = p.options.Disposition.AddressRows
		}
		switch choice {
		case "":
			p.unsupported(loc, fmt.Sprintf("ambiguous %s %s %s: select observation, manual or skip", r.Type, name, r.Value))
		case "skip":
			p.exclude(loc, "skipped legacy address "+name)
		case "observation":
			p.legacy(loc, r)
		case "manual":
			p.record(loc, r, true)
		default:
			return fmt.Errorf("%s: invalid address selection %q", loc, choice)
		}
	}
	return rows.Err()
}
