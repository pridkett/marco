package dnsserver

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/contract"
)

func withEDE(msg *dns.Msg, code uint16, text string) *dns.Msg {
	msg.SetEdns0(1232, false)
	opt := msg.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: code, ExtraText: text})
	return msg
}

func TestUpstreamBlockSignals(t *testing.T) {
	const nextDNS = "Blocked by NextDNS: blocklist:nextdns-recommended"
	reply := func(records ...string) *dns.Msg {
		msg := new(dns.Msg)
		for _, record := range records {
			msg.Answer = append(msg.Answer, rr(t, record))
		}
		return msg
	}
	for _, tc := range []struct {
		name    string
		msg     *dns.Msg
		blocked bool
		detail  string
	}{
		{"nextdns A", withEDE(reply("ads.example. 300 IN A 0.0.0.0"), dns.ExtendedErrorCodeFiltered, nextDNS), true, nextDNS},
		{"nextdns empty TXT", withEDE(reply(), dns.ExtendedErrorCodeFiltered, nextDNS), true, nextDNS},
		{"EDE without text", withEDE(reply(), dns.ExtendedErrorCodeBlocked, ""), true, "EDE 15 Blocked"},
		{"censored", withEDE(reply(), dns.ExtendedErrorCodeCensored, "x"), true, "x"},
		{"prohibited", withEDE(reply(), dns.ExtendedErrorCodeProhibited, "y"), true, "y"},
		{"unrelated EDE", withEDE(reply("ok.example. 60 IN A 192.0.2.1"), dns.ExtendedErrorCodeStaleAnswer, ""), false, ""},
		{"sinkhole A", reply("ads.example. 60 IN A 0.0.0.0"), true, "Unspecified address answer"},
		{"sinkhole AAAA", reply("ads.example. 60 IN AAAA ::"), true, "Unspecified address answer"},
		{"sinkhole behind CNAME", reply("a.example. 60 IN CNAME b.example.", "b.example. 60 IN A 0.0.0.0"), true, "Unspecified address answer"},
		{"mixed addresses", reply("a.example. 60 IN A 0.0.0.0", "a.example. 60 IN A 192.0.2.1"), false, ""},
		{"normal answer", reply("a.example. 60 IN A 192.0.2.1"), false, ""},
		{"empty answer", reply(), false, ""},
		{"CNAME only", reply("a.example. 60 IN CNAME b.example."), false, ""},
	} {
		blocked, detail := upstreamBlock(tc.msg)
		if blocked != tc.blocked || detail != tc.detail {
			t.Errorf("%s: got (%v, %q), want (%v, %q)", tc.name, blocked, detail, tc.blocked, tc.detail)
		}
	}
}

func TestUpstreamBlockDetailIsBounded(t *testing.T) {
	msg := withEDE(new(dns.Msg), dns.ExtendedErrorCodeFiltered,
		"  bad\x00\x1b[31m\nnewsé"+strings.Repeat("z", 500))
	_, detail := upstreamBlock(msg)
	if len(detail) != maxBlockDetail || strings.ContainsAny(detail, "\x00\x1b\né") || !strings.HasPrefix(detail, "bad[31mnews") {
		t.Fatalf("unsanitized detail %q (%d bytes)", detail, len(detail))
	}
}

type blockingUpstream struct {
	calls int
}

func (u *blockingUpstream) Exchange(_ context.Context, _ string, query *dns.Msg) (*dns.Msg, bool, error) {
	u.calls++
	reply := new(dns.Msg).SetReply(query)
	reply.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{0, 0, 0, 0},
	}}
	return withEDE(reply, dns.ExtendedErrorCodeFiltered, "Blocked by NextDNS: blocklist:fixture"), u.calls > 1, nil
}

func TestEvaluateRecordsUpstreamBlocks(t *testing.T) {
	policies := fixturePolicies{allows: map[string]contract.Decision{
		"allowed.example.": {Allowed: true, Reason: "manual-allow", Rule: "local-allow"},
	}}
	upstream := &blockingUpstream{}
	view := &contract.View{Policies: policies, Local: fixtureLocal{}, Upstream: upstream}
	for _, want := range []struct{ name, origin, cache string }{
		{"tracker.example.", "upstream", "miss"},
		{"tracker.example.", "cache", "hit"},
		// A local allow rule cannot stop the upstream from filtering, so the
		// upstream's reason must replace it rather than report an allow.
		{"allowed.example.", "cache", "hit"},
	} {
		query := new(dns.Msg).SetQuestion(want.name, dns.TypeA)
		_, resolved := evaluate(t.Context(), view, contract.Input{
			Name: want.name, Peer: netip.MustParseAddr("192.0.2.2"), Type: dns.TypeA, Recursion: true,
		}, query)
		got := resolved.result
		if got.Reason != "upstream-blocked" || got.Rule != "Blocked by NextDNS: blocklist:fixture" ||
			got.Origin != want.origin || got.Cache != want.cache || got.RCode != dns.RcodeSuccess {
			t.Errorf("%s: got %+v", want.name, got)
		}
		if a, ok := resolved.message.Answer[0].(*dns.A); !ok || !a.A.IsUnspecified() || resolved.extended {
			t.Errorf("%s: client reply was changed: %v", want.name, resolved.message)
		}
	}
}
