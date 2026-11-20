package dnsserver

import (
	"context"
	"time"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
)

type answer struct {
	result   contract.Result
	message  *dns.Msg
	extended bool
}

// Preview runs the local and policy portions of the resolver without making a
// network request. A permitted external lookup is reported as external-eligible.
func Preview(view *contract.View, input contract.Input) (contract.Selection, contract.Result) {
	input.Name = dns.CanonicalName(input.Name)
	if input.Time.IsZero() {
		input.Time = time.Now()
	}
	selected, resolved := evaluate(context.Background(), view, input, nil)
	return selected, resolved.result
}

func evaluate(ctx context.Context, view *contract.View, in contract.Input, query *dns.Msg) (contract.Selection, answer) {
	if view == nil || view.Policies == nil || view.Local == nil {
		return contract.Selection{}, outcome(dns.RcodeServerFailure, "server", "view-unavailable")
	}
	selected := view.Policies.Select(in.Peer, in.Time)
	if selected.Policy.Mode == config.DenyAll {
		return selected, outcome(dns.RcodeRefused, "policy", "client-deny-all")
	}
	manual := view.Policies.Manual(selected, in.Name)
	ruleRef := manual.Rule
	if manual.Blocked {
		return selected, policyBlock(manual)
	}
	local := view.Local.Lookup(in.Name, in.Type)
	for _, rr := range local.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			rule := view.Policies.Manual(selected, dns.CanonicalName(cname.Target))
			if rule.Blocked {
				return selected, policyBlock(rule)
			}
		}
	}
	target := in.Name
	if local.Found {
		if local.PublicTarget == "" {
			reason := "local-answer"
			switch {
			case local.Suppressed:
				reason = "local-suppression"
			case local.Code != dns.RcodeSuccess || len(local.Answer) == 0:
				reason = "local-negative"
			}
			resolved := outcome(local.Code, "local", reason)
			resolved.result.Rule = ruleRef
			resolved.message = &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: local.Code, Authoritative: local.Authoritative},
				Answer: copyRecords(local.Answer),
				Ns:     copyRecords(local.Authority),
			}
			return selected, resolved
		}
		target = dns.CanonicalName(local.PublicTarget)
		manual = view.Policies.Manual(selected, target)
	}

	if !in.Recursion {
		return selected, outcome(dns.RcodeRefused, "policy", "recursion-disabled")
	}
	if selected.Policy.Mode == config.LocalOnly {
		return selected, outcome(dns.RcodeRefused, "policy", "client-local-only")
	}
	rule := externalRule(view.Policies, selected, in, target, manual)
	if rule.Blocked {
		return selected, policyBlock(rule)
	}
	if rule.Rule != "" {
		ruleRef = rule.Rule
	}
	if query == nil {
		resolved := outcome(dns.RcodeSuccess, "upstream", "external-eligible")
		resolved.result.Rule = ruleRef
		return selected, resolved
	}
	if view.Upstream == nil {
		return selected, outcome(dns.RcodeServerFailure, "upstream", "upstream-error")
	}
	if target != in.Name {
		query = query.Copy()
		query.Question[0].Name = target
	}
	reply, hit, err := view.Upstream.Exchange(ctx, selected.Policy.Pool, query)
	cache := "miss"
	if hit {
		cache = "hit"
	}
	if err != nil || reply == nil {
		resolved := outcome(dns.RcodeServerFailure, "upstream", "upstream-error")
		resolved.result.Cache = cache
		return selected, resolved
	}

	blocked, tooDeep := checkTargets(reply.Answer, target, func(name string) contract.Decision {
		return externalRule(view.Policies, selected, in, name, view.Policies.Manual(selected, name))
	})
	if blocked.Blocked {
		resolved := policyBlock(blocked)
		resolved.result.Cache = cache
		return selected, resolved
	}
	if tooDeep {
		resolved := outcome(dns.RcodeServerFailure, "upstream", "upstream-alias-depth")
		resolved.result.Cache = cache
		return selected, resolved
	}

	origin := "upstream"
	if hit {
		origin = "cache"
	}
	reason := "upstream-answer"
	if reply.Rcode == dns.RcodeNameError || len(reply.Answer) == 0 {
		reason = "upstream-negative"
	}
	resolved := outcome(reply.Rcode, origin, reason)
	resolved.result.Rule = ruleRef
	resolved.result.Cache = cache
	if local.PublicTarget != "" {
		reply.Answer = append(copyRecords(local.Answer), reply.Answer...)
		reply.AuthenticatedData = false
		reply.Authoritative = false
	}
	resolved.message = reply
	return selected, resolved
}

func externalRule(policies contract.Policies, selection contract.Selection, in contract.Input, name string, manual contract.Decision) contract.Decision {
	if manual.Blocked || manual.Allowed || selection.Policy.Mode == config.Unfiltered {
		return manual
	}
	return policies.External(selection, name, in.Type, in.Time)
}

func copyRecords(in []dns.RR) []dns.RR {
	if len(in) == 0 {
		return nil
	}
	out := make([]dns.RR, len(in))
	for i, rr := range in {
		out[i] = dns.Copy(rr)
	}
	return out
}

func outcome(rcode int, origin, reason string) answer {
	return answer{result: contract.Result{RCode: rcode, Origin: origin, Reason: reason}}
}

func policyBlock(decision contract.Decision) answer {
	reason := decision.Reason
	if reason == "" {
		reason = "manual-deny"
	}
	resolved := outcome(dns.RcodeNameError, "policy", reason)
	resolved.result.Rule = decision.Rule
	resolved.extended = true
	return resolved
}

func checkTargets(records []dns.RR, start string, decide func(string) contract.Decision) (contract.Decision, bool) {
	// Most answers have no aliases. Allocate a graph only when there is an edge.
	var targets map[string][]string
	for _, rr := range records {
		var target string
		switch record := rr.(type) {
		case *dns.CNAME:
			target = record.Target
		case *dns.HTTPS:
			if record.Priority == 0 {
				target = record.Target
			}
		case *dns.SVCB:
			if record.Priority == 0 {
				target = record.Target
			}
		}
		if target == "" || target == "." {
			continue
		}
		if targets == nil {
			targets = make(map[string][]string)
		}
		owner := dns.CanonicalName(rr.Header().Name)
		targets[owner] = append(targets[owner], dns.CanonicalName(target))
	}

	const maxTargets = 32
	if len(targets[start]) == 0 {
		return contract.Decision{}, false
	}
	seen := make(map[string]bool)
	var visit func(string) (contract.Decision, bool)
	visit = func(owner string) (contract.Decision, bool) {
		for _, target := range targets[owner] {
			if seen[target] {
				continue
			}
			if len(seen) == maxTargets {
				return contract.Decision{}, true
			}
			seen[target] = true
			if rule := decide(target); rule.Blocked {
				return rule, false
			}
			if rule, tooDeep := visit(target); rule.Blocked || tooDeep {
				return rule, tooDeep
			}
		}
		return contract.Decision{}, false
	}
	return visit(start)
}
