package filter

import (
	"fmt"
	"slices"
	"strings"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/config"
)

type ServiceRule struct {
	Text      string
	Pattern   string
	Scope     string
	Condition string

	excludeType uint16
	exceptions  []string
}

type qualifiedServiceRule struct {
	ServiceRule
	pattern dnsPattern
}

type ServiceIndex struct {
	domains   Index
	qualified []qualifiedServiceRule
}

func CompileService(spec config.Service) (*ServiceIndex, error) {
	index := &ServiceIndex{domains: make(Index)}
	for _, domain := range spec.Domains {
		if domain.Allow {
			return nil, fmt.Errorf("service contains an allow rule")
		}
		if err := index.domains.Add(domain); err != nil {
			return nil, err
		}
	}
	for _, raw := range spec.Rules {
		rule, err := serviceRule(raw)
		if err != nil {
			return nil, err
		}
		domain, err := ParseRule(rule.Pattern)
		// Leading-dot and wildcard forms need hostname pattern matching.
		if err == nil && len(rule.exceptions) == 0 && rule.excludeType == 0 {
			if err := index.domains.Add(domain); err != nil {
				return nil, err
			}
			continue
		}
		if len(index.qualified) >= 128 {
			return nil, fmt.Errorf("service has more than 128 pattern or conditional rules")
		}
		var pattern dnsPattern
		if strings.HasPrefix(rule.Pattern, "/") {
			pattern, _, err = compileDNSPattern(rule.Pattern, false)
		} else {
			pattern, _, err = compileGlob(rule.Pattern, Match{Found: true, Name: raw}, false)
		}
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", raw, err)
		}
		pattern.hit.Name = raw
		index.qualified = append(index.qualified, qualifiedServiceRule{rule, pattern})
	}
	return index, nil
}

func (i *ServiceIndex) Match(name string, kind uint16) Match {
	if i == nil {
		return Match{}
	}
	best := i.domains.Match(name, false)
	host := strings.TrimSuffix(name, ".")
	for _, rule := range i.qualified {
		if rule.excludeType != 0 && rule.excludeType == kind || !rule.pattern.hit.Wins(best, false) {
			continue
		}
		if slices.ContainsFunc(rule.exceptions, func(exception string) bool {
			return name == exception || strings.HasSuffix(name, "."+exception)
		}) {
			continue
		}
		if rule.pattern.rx.MatchString(host) {
			best = rule.pattern.hit
		}
	}
	return best
}

func DescribeService(spec config.Service) []ServiceRule {
	rules := make([]ServiceRule, 0, len(spec.Domains)+len(spec.Rules))
	for _, rule := range spec.Domains {
		scope := "Exact hostname"
		if rule.Suffix {
			scope = "Hostname and subdomains"
		}
		rules = append(rules, ServiceRule{Text: rule.Name, Pattern: rule.Name, Scope: scope})
	}
	for _, raw := range spec.Rules {
		rule, _ := serviceRule(raw)
		rules = append(rules, rule)
	}
	return rules
}

func serviceRule(raw string) (ServiceRule, error) {
	rule := ServiceRule{Text: raw}
	if len(raw) == 0 || len(raw) > maxPatternBytes || strings.HasPrefix(raw, "@@") {
		return rule, fmt.Errorf("invalid service rule %q", raw)
	}
	pattern, option, _ := strings.Cut(raw, "$")
	if strings.HasPrefix(pattern, "/") && strings.HasSuffix(raw, "/") {
		pattern, option = raw, ""
	}
	// Some registry entries have whitespace preceding their end marker.
	if prefix, end := strings.CutSuffix(pattern, "^"); end {
		pattern = strings.TrimSpace(prefix) + "^"
	}
	rule.Pattern = pattern
	switch {
	case strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/"):
		rule.Scope = "Regular expression"
	case strings.Contains(pattern, "*"):
		rule.Scope = "Wildcard pattern"
	case strings.HasPrefix(pattern, "||") && strings.HasSuffix(pattern, "^"):
		rule.Scope = "Hostname and subdomains"
	case strings.HasPrefix(pattern, "||"):
		rule.Scope = "Hostname prefix at a label boundary"
	case strings.HasPrefix(pattern, "|"):
		rule.Scope = "Starts at the hostname"
	default:
		rule.Scope = "Hostname pattern"
	}
	switch {
	case option == "":
	case option == "dnsrewrite=NXDOMAIN;;":
		rule.Condition = "Returns NXDOMAIN"
	case strings.HasPrefix(option, "dnstype=~"):
		typeName := strings.ToUpper(strings.TrimPrefix(option, "dnstype=~"))
		rule.excludeType = dns.StringToType[typeName]
		if rule.excludeType == 0 {
			return rule, fmt.Errorf("unknown DNS type in service rule %q", raw)
		}
		rule.Condition = "Except " + typeName + " queries"
	case strings.HasPrefix(option, "denyallow="):
		var shown []string
		for _, name := range strings.Split(strings.TrimPrefix(option, "denyallow="), "|") {
			exception, err := config.Name(name)
			if err != nil {
				return rule, fmt.Errorf("invalid exception in service rule %q", raw)
			}
			rule.exceptions = append(rule.exceptions, exception)
			shown = append(shown, strings.TrimSuffix(exception, "."))
		}
		rule.Condition = "Except " + strings.Join(shown, ", ") + " and their subdomains"
	default:
		return rule, fmt.Errorf("unsupported modifier in service rule %q", raw)
	}
	return rule, nil
}
