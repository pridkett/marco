// Package filter loads subscription artifacts and matches DNS names at label boundaries.
package filter

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"strings"

	"github.com/pridkett/marco/internal/config"
)

const (
	MaxBytes      = 32 << 20
	MaxRules      = 1_000_000
	MaxIndexRules = 1_250_000
)

type Bits uint8

const (
	exactDeny Bits = 1 << iota
	exactAllow
	suffixDeny
	suffixAllow
)

type Index map[string]Bits

type Match struct {
	Found     bool
	Allow     bool
	Exact     bool
	Size      int
	Name      string
	Important bool
}

func (m Match) Wins(against Match, allowTie bool) bool {
	if !m.Found {
		return false
	}
	if !against.Found {
		return true
	}
	if m.Important != against.Important {
		return m.Important
	}
	if m.Exact != against.Exact {
		return m.Exact
	}
	if m.Size != against.Size {
		return m.Size > against.Size
	}
	if m.Allow != against.Allow {
		return m.Allow == allowTie
	}
	return false
}

func (i Index) Add(rule config.Rule) error {
	name, err := config.Name(rule.Name)
	if err != nil {
		return err
	}
	i.add(name, rule.Suffix, rule.Allow)
	return nil
}

func (i Index) add(name string, suffix, allow bool) {
	var kind Bits = exactDeny
	if allow {
		kind <<= 1
	}
	if suffix {
		kind <<= 2
	}
	i[name] |= kind
}

func (i Index) Match(name string, allowTie bool) Match {
	for suffix := name; suffix != ""; {
		bits := i[suffix]
		if suffix == name && bits&(exactDeny|exactAllow) != 0 {
			return Match{Found: true, Allow: bits&exactAllow != 0 && (allowTie || bits&exactDeny == 0), Exact: true, Size: len(suffix), Name: suffix}
		}
		if bits&(suffixDeny|suffixAllow) != 0 {
			return Match{Found: true, Allow: bits&suffixAllow != 0 && (allowTie || bits&suffixDeny == 0), Size: len(suffix), Name: suffix}
		}
		_, suffix, _ = strings.Cut(suffix, ".")
	}
	return Match{}
}

// ParseRule parses a standalone plain or AdGuard DNS rule.
func ParseRule(line string) (config.Rule, error) {
	rule := config.Rule{}
	if strings.HasPrefix(line, "@@||") {
		rule.Allow = true
		line = line[2:]
	}
	if strings.HasPrefix(line, "||") {
		if !strings.HasSuffix(line, "^") {
			return rule, fmt.Errorf("unsupported AdGuard suffix rule")
		}
		rule.Suffix = true
		line = line[2 : len(line)-1]
	}
	if _, err := netip.ParseAddr(line); err == nil {
		return rule, fmt.Errorf("expected a domain, got an IP address")
	}
	var err error
	rule.Name, err = config.Name(line)
	return rule, err
}

// SubscriptionIndex combines the domain index with an optional DNS pattern matcher.
type SubscriptionIndex struct {
	domains  Index
	patterns patternIndex
}

func (i *SubscriptionIndex) Len() int {
	return len(i.domains) + i.patterns.count
}

func (i *SubscriptionIndex) Match(name string, allowTie bool) Match {
	if i == nil {
		return Match{}
	}
	return i.patterns.match(name, i.domains.Match(name, allowTie), allowTie)
}

func Parse(body []byte, source config.Subscription) (*SubscriptionIndex, int, error) {
	if len(body) > MaxBytes {
		return nil, 0, fmt.Errorf("subscription exceeds %d expanded bytes", MaxBytes)
	}
	index := &SubscriptionIndex{domains: make(Index)}
	advanced := source.Format == config.AdGuardFormat
	var disabled map[string]bool
	if advanced {
		var err error
		if disabled, err = disabledPatterns(body); err != nil {
			return nil, 0, err
		}
	}

	scanner := bufio.NewScanner(bytes.NewReader(body))
	count, lineNo, invalid := 0, 0, 0
	var problems []string
	recordProblem := func(problem string) {
		invalid++
		if len(problems) < 8 {
			problems = append(problems, fmt.Sprintf("line %d: %s", lineNo, problem))
		}
	}
	for scanner.Scan() {
		lineNo++
		raw := subscriptionLine(scanner.Text())
		if raw == "" {
			continue
		}
		fields := strings.Fields(raw)
		if len(fields) > 1 {
			if _, err := netip.ParseAddr(fields[0]); err == nil {
				for _, owner := range fields[1:] {
					rule, err := ParseRule(owner)
					if err != nil || rule.Suffix || rule.Allow {
						recordProblem("invalid hosts owner")
					} else {
						index.domains.add(rule.Name, false, source.Allowlist)
						count++
					}
				}
				if count > MaxRules {
					return nil, 0, fmt.Errorf("subscription exceeds %d usable rules", MaxRules)
				}
				continue
			}
		}
		rule, err := ParseRule(raw)
		switch {
		case advanced && disabled[strings.ToLower(raw)]:
			continue
		case advanced && strings.HasSuffix(raw, "$badfilter"):
			// Validated in the first pass.
			continue
		case err == nil:
			index.domains.add(rule.Name, rule.Suffix, rule.Allow || source.Allowlist)
		case advanced:
			if problem := index.patterns.add(raw, source.Allowlist); problem != nil {
				recordProblem(problem.Error())
				continue
			}
		default:
			recordProblem(syntaxKind(raw))
			continue
		}
		count++
		if count > MaxRules {
			return nil, 0, fmt.Errorf("subscription exceeds %d usable rules", MaxRules)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, fmt.Errorf("line %d exceeds scanner limit or could not be read", lineNo+1)
	}
	if invalid != 0 {
		return nil, 0, fmt.Errorf("%d unsupported subscription lines (%s)", invalid, strings.Join(problems, "; "))
	}
	if count == 0 && !source.AllowEmpty {
		return nil, 0, fmt.Errorf("subscription contains no usable rules")
	}
	return index, count, nil
}

func subscriptionLine(text string) string {
	line := strings.TrimSpace(strings.TrimPrefix(text, "\uFEFF"))
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") ||
		strings.EqualFold(line, "[Adblock Plus 2.0]") {
		return ""
	}
	raw, _, _ := strings.Cut(line, " #")
	return strings.TrimSpace(raw)
}

func syntaxKind(line string) string {
	switch {
	case strings.Contains(line, "$dnsrewrite"):
		return "DNS rewrite"
	case strings.Contains(line, "$client"):
		return "client-specific rule"
	case strings.Contains(line, "$"):
		return "rule modifier"
	case strings.HasPrefix(line, "/") || strings.HasPrefix(line, "@@/"):
		return "regular expression"
	default:
		return "unrecognized domain or rule syntax"
	}
}
