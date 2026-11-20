package filter

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

const (
	maxPatterns      = 2048
	maxUnindexed     = 64
	maxPatternBytes  = 1024
	patternKeyLength = 4
)

type dnsPattern struct {
	rx  *regexp.Regexp
	url bool
	hit Match
}

type patternIndex struct {
	keyed   map[string][]dnsPattern
	unkeyed []dnsPattern
	count   int
}

func disabledPatterns(body []byte) (map[string]bool, error) {
	disabled := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for line := 1; scanner.Scan(); line++ {
		raw := subscriptionLine(scanner.Text())
		base, disabledHere := strings.CutSuffix(raw, "$badfilter")
		if !disabledHere {
			continue
		}
		if _, err := ParseRule(base); err != nil {
			if _, _, err := compileDNSPattern(base, false); err != nil {
				return nil, fmt.Errorf("line %d: invalid rule for badfilter: %w", line, err)
			}
		}
		if len(disabled) == maxPatterns {
			return nil, fmt.Errorf("subscription exceeds %d badfilter entries", maxPatterns)
		}
		disabled[strings.ToLower(base)] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan subscription: %w", err)
	}
	return disabled, nil
}

func (i *patternIndex) add(raw string, allowlist bool) error {
	if i.count >= maxPatterns {
		return fmt.Errorf("subscription exceeds %d DNS patterns", maxPatterns)
	}
	pattern, key, err := compileDNSPattern(raw, allowlist)
	if err != nil {
		return err
	}
	if key == "" {
		if len(i.unkeyed) >= maxUnindexed {
			return fmt.Errorf("subscription exceeds %d DNS patterns without an index key", maxUnindexed)
		}
		i.unkeyed = append(i.unkeyed, pattern)
	} else {
		if i.keyed == nil {
			i.keyed = make(map[string][]dnsPattern)
		}
		i.keyed[key] = append(i.keyed[key], pattern)
	}
	i.count++
	return nil
}

func (i *patternIndex) match(name string, best Match, allowTie bool) Match {
	if i.count == 0 {
		return best
	}
	host := strings.TrimSuffix(name, ".")
	var url string
	check := func(pattern dnsPattern) {
		if !pattern.hit.Wins(best, allowTie) {
			return
		}
		target := host
		if pattern.url {
			if url == "" {
				url = "http://" + host
			}
			target = url
		}
		if pattern.rx.MatchString(target) {
			best = pattern.hit
		}
	}
	for _, pattern := range i.unkeyed {
		check(pattern)
	}
	for at := range len(host) - patternKeyLength + 1 {
		for _, pattern := range i.keyed[host[at:at+patternKeyLength]] {
			check(pattern)
		}
	}
	return best
}

func compileDNSPattern(raw string, allowlist bool) (dnsPattern, string, error) {
	if len(raw) > maxPatternBytes {
		return dnsPattern{}, "", fmt.Errorf("DNS pattern exceeds %d bytes", maxPatternBytes)
	}
	rule, allow := strings.CutPrefix(raw, "@@")
	hit := Match{Found: true, Allow: allow || allowlist, Name: raw}
	if strings.HasPrefix(rule, "/") {
		if end := strings.LastIndexByte(rule, '/'); end > 0 &&
			(end == len(rule)-1 || strings.HasPrefix(rule[end+1:], "$")) {
			if end == 1 {
				return dnsPattern{}, "", fmt.Errorf("empty DNS expression")
			}
			if modifier := rule[end+1:]; modifier != "" && modifier != "$important" {
				return dnsPattern{}, "", fmt.Errorf("unsupported DNS rule modifier")
			}
			hit.Important = end < len(rule)-1
			rx, err := regexp.Compile("(?i)" + rule[1:end])
			if err != nil {
				return dnsPattern{}, "", fmt.Errorf("invalid DNS expression")
			}
			// A leading literal from RE2 is mandatory and safe to index.
			literal, _ := rx.LiteralPrefix()
			hit.Size = len(literal)
			return dnsPattern{rx: rx, hit: hit}, patternKey(strings.ToLower(literal)), nil
		}
	}

	rule, modifier, _ := strings.Cut(rule, "$")
	if modifier != "" && modifier != "important" || strings.HasSuffix(raw, "$") {
		return dnsPattern{}, "", fmt.Errorf("unsupported DNS rule modifier")
	}
	hit.Important = modifier == "important"
	if ipRule, err := ParseRule(rule); err == nil && !ipRule.Suffix {
		// Keep Marco's plain-domain semantics for a modified exact rule.
		rule = "|" + strings.TrimSuffix(ipRule.Name, ".") + "|"
		return compileGlob(rule, hit, false)
	}
	useURL := strings.HasPrefix(rule, "://") || strings.HasPrefix(rule, "http://") ||
		strings.HasPrefix(rule, "https://") || strings.HasPrefix(rule, "|") && !strings.HasPrefix(rule, "||")
	return compileGlob(rule, hit, useURL)
}

func compileGlob(rule string, hit Match, useURL bool) (dnsPattern, string, error) {
	var expression strings.Builder
	expression.WriteString("(?i)")
	if body, anchored := strings.CutPrefix(rule, "||"); anchored {
		expression.WriteString(`(?:^|\.)`)
		rule = body
	} else if body, anchored := strings.CutPrefix(rule, "|"); anchored {
		expression.WriteByte('^')
		rule = body
	}
	rule, end := strings.CutSuffix(rule, "|")
	longest := ""
	for rest := rule; rest != ""; {
		k := strings.IndexAny(rest, "*^")
		if k < 0 {
			k = len(rest)
		}
		literal := rest[:k]
		for _, c := range literal {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._:/", c) {
				return dnsPattern{}, "", fmt.Errorf("unsupported DNS pattern syntax")
			}
		}
		expression.WriteString(regexp.QuoteMeta(literal))
		hit.Size += len(literal)
		if len(literal) > len(longest) {
			longest = literal
		}
		if k == len(rest) {
			break
		}
		if rest[k] == '*' {
			expression.WriteString(".*")
		} else {
			expression.WriteString(`(?:$|[^a-z0-9_.%-])`)
		}
		rest = rest[k+1:]
	}
	if hit.Size == 0 {
		return dnsPattern{}, "", fmt.Errorf("DNS pattern requires a literal")
	}
	if end {
		expression.WriteByte('$')
	}
	rx, err := regexp.Compile(expression.String())
	if err != nil {
		return dnsPattern{}, "", fmt.Errorf("invalid DNS pattern")
	}
	if useURL {
		// URL prefixes include separators outside the DNS name.
		longest = ""
		for field := range strings.FieldsFuncSeq(rule, func(c rune) bool {
			return strings.ContainsRune(":/^*", c)
		}) {
			if field != "http" && field != "https" && len(field) > len(longest) {
				longest = field
			}
		}
	}
	return dnsPattern{rx: rx, url: useURL, hit: hit}, patternKey(strings.ToLower(longest)), nil
}

func patternKey(literal string) string {
	if len(literal) < patternKeyLength {
		return ""
	}
	// Start of the longest literal avoids grouping by common TLDs.
	return literal[:patternKeyLength]
}
