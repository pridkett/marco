package dnsserver

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
)

type fixtureLocal map[string]contract.LocalResult

func (f fixtureLocal) Lookup(name string, _ uint16) contract.LocalResult { return f[name] }

type fixturePolicies struct {
	local  netip.Addr
	denies map[string]contract.Decision
	allows map[string]contract.Decision
	blocks map[string]contract.Decision
}

func (f fixturePolicies) Select(ip netip.Addr, _ time.Time) contract.Selection {
	mode := config.Filtered
	if ip == f.local {
		mode = config.LocalOnly
	}
	return contract.Selection{Policy: config.Policy{Mode: mode}}
}

func (f fixturePolicies) Manual(_ contract.Selection, name string) contract.Decision {
	if decision, ok := f.denies[name]; ok {
		return decision
	}
	return f.allows[name]
}

func (f fixturePolicies) External(_ contract.Selection, name string, _ uint16, _ time.Time) contract.Decision {
	return f.blocks[name]
}

type fixtureUpstream struct {
	records []dns.RR
	calls   atomic.Int64
}

func (f *fixtureUpstream) Exchange(_ context.Context, _ string, query *dns.Msg) (*dns.Msg, bool, error) {
	hit := f.calls.Add(1) > 1
	reply := new(dns.Msg)
	reply.SetReply(query)
	reply.AuthenticatedData = true
	reply.Answer = copyRecords(f.records)
	return reply, hit, nil
}

func rr(t *testing.T, row string) dns.RR {
	t.Helper()
	record, err := dns.NewRR(row)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func startFixture(t *testing.T, address string, prefix netip.Prefix, view *contract.View) *Server {
	t.Helper()
	server, err := Listen(Options{Address: address, Allow: []netip.Prefix{prefix}, View: func() *contract.View { return view }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	if !server.Ready() {
		t.Fatal("listener is not ready after bind")
	}
	return server
}

func exchange(t *testing.T, server *Server, network string, request *dns.Msg) *dns.Msg {
	t.Helper()
	client := &dns.Client{Net: network, Timeout: time.Second, UDPSize: 4096}
	reply, _, err := client.Exchange(request, server.Address())
	if err != nil {
		t.Fatal(err)
	}
	return reply
}

func TestLANWireAndLimits(t *testing.T) {
	small := rr(t, "host.home.arpa. 60 IN A 192.0.2.5")
	var large []dns.RR
	for i := range 10 {
		payload := strings.Repeat(string(rune('a'+i)), 200)
		large = append(large, rr(t, `big.home.arpa. 60 IN TXT "`+payload+`"`))
	}
	soa := rr(t, "home.arpa. 60 IN SOA marco.home.arpa. admin.home.arpa. 1 60 60 60 60")
	upstream := &fixtureUpstream{}
	view := &contract.View{
		Policies: fixturePolicies{},
		Local: fixtureLocal{
			"host.home.arpa.": {Found: true, Authoritative: true, Answer: []dns.RR{small}},
			"big.home.arpa.":  {Found: true, Authoritative: true, Answer: large},
			"bad.home.arpa.":  {Found: true, Authoritative: true, Code: dns.RcodeNameError, Authority: []dns.RR{soa}},
		},
		Upstream: upstream,
	}
	server := startFixture(t, "127.0.0.1:0", netip.MustParsePrefix("127.0.0.0/8"), view)
	query := new(dns.Msg)
	query.SetQuestion("Host.Home.ARPA.", dns.TypeA)
	query.Id = 1234
	query.RecursionDesired = false
	udp := exchange(t, server, "udp", query)
	tcp := exchange(t, server, "tcp", query)
	if !reflect.DeepEqual(udp, tcp) || udp.Id != query.Id || udp.Question[0] != query.Question[0] ||
		udp.RecursionDesired || !udp.RecursionAvailable || !udp.Authoritative || udp.AuthenticatedData ||
		len(udp.Answer) != 1 {
		t.Fatalf("reply envelope differs: UDP %v TCP %v", udp, tcp)
	}

	query.SetQuestion("big.home.arpa.", dns.TypeTXT)
	plain := exchange(t, server, "udp", query)
	if !plain.Truncated || len(plain.Answer) != 2 || plain.IsEdns0() != nil {
		t.Fatalf("unexpected 512-byte reply: %v", plain)
	}
	query.SetEdns0(4096, true)
	edns := exchange(t, server, "udp", query)
	if !edns.Truncated || len(edns.Answer) <= len(plain.Answer) || edns.IsEdns0().UDPSize() != 1232 {
		t.Fatalf("unexpected capped EDNS reply: %v", edns)
	}
	tcp = exchange(t, server, "tcp", query)
	if tcp.Truncated || len(tcp.Answer) != len(large) {
		t.Fatalf("retry did not return complete reply: %v", tcp)
	}

	query.SetQuestion("bad.home.arpa.", dns.TypeA)
	private := exchange(t, server, "udp", query)
	if private.Rcode != dns.RcodeNameError || !private.Authoritative || len(private.Ns) != 1 {
		t.Fatalf("private miss: %v", private)
	}

	query.SetQuestion("unknown.public.example.", dns.TypeA)
	query.RecursionDesired = false
	refused := exchange(t, server, "udp", query)
	if refused.Rcode != dns.RcodeRefused || upstream.calls.Load() != 0 {
		t.Fatalf("RD=0 caused external resolution: %v", refused)
	}

	query.RecursionDesired = true
	exchange(t, server, "udp", query)
	if upstream.calls.Load() != 1 {
		t.Fatal("external miss was not forwarded")
	}
}

func TestLANAdmissionAndValidation(t *testing.T) {
	view := &contract.View{Policies: fixturePolicies{}, Local: fixtureLocal{}}
	t.Run("unauthorized IPv4", func(t *testing.T) {
		server := startFixture(t, "127.0.0.1:0", netip.MustParsePrefix("192.0.2.0/24"), view)
		for _, network := range []string{"udp", "tcp"} {
			client := &dns.Client{Net: network, Timeout: 100 * time.Millisecond}
			query := new(dns.Msg)
			query.SetQuestion("outside.example.", dns.TypeA)
			if reply, _, err := client.Exchange(query, server.Address()); err == nil || reply != nil {
				t.Fatalf("%s received unauthorized reply: %v", network, reply)
			}
		}
	})

	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	probe.Close()
	server := startFixture(t, "[::]:0", netip.MustParsePrefix("::1/128"), view)
	query := new(dns.Msg)
	query.SetQuestion("outside.example.", dns.TypeA)
	query.RecursionDesired = false
	for _, network := range []string{"udp", "tcp"} {
		client := &dns.Client{Net: network, Timeout: time.Second}
		_, port, _ := net.SplitHostPort(server.Address())
		if reply, _, err := client.Exchange(query, net.JoinHostPort("::1", port)); err != nil || reply.Rcode != dns.RcodeRefused {
			t.Fatalf("%s denied authorized IPv6: %v %v", network, reply, err)
		}
		client.Timeout = 100 * time.Millisecond
		if reply, _, err := client.Exchange(query, net.JoinHostPort("127.0.0.1", port)); err == nil || reply != nil {
			t.Fatalf("%s responded to IPv4 against IPv6 ACL: %v", network, reply)
		}
	}

	query = new(dns.Msg)
	query.Id = 222
	for _, tc := range []struct {
		name  string
		query *dns.Msg
		code  int
	}{
		{"no question", query.Copy(), dns.RcodeFormatError},
		{"transfer", new(dns.Msg).SetQuestion("zone.example.", dns.TypeAXFR), dns.RcodeRefused},
		{"update", new(dns.Msg).SetUpdate("zone.example."), dns.RcodeRefused},
		{"other class", &dns.Msg{Question: []dns.Question{{Name: "host.", Qtype: dns.TypeTXT, Qclass: dns.ClassCHAOS}}}, dns.RcodeNotImplemented},
		{"unknown EDNS version", ednsVersionQuery(), dns.RcodeBadVers},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, port, _ := net.SplitHostPort(server.Address())
			reply, _, err := (&dns.Client{Net: "udp6", Timeout: time.Second}).Exchange(tc.query, net.JoinHostPort("::1", port))
			if err != nil || reply.Rcode != tc.code {
				t.Fatalf("unexpected reply: %v %v", reply, err)
			}
		})
	}
}

func ednsVersionQuery() *dns.Msg {
	query := new(dns.Msg).SetQuestion("host.example.", dns.TypeA).SetEdns0(1232, false)
	query.IsEdns0().SetVersion(1)
	return query
}

func TestPolicyChecksOnLocalAndCachedAnswers(t *testing.T) {
	filtered := netip.MustParseAddr("192.0.2.2")
	localOnly := netip.MustParseAddr("192.0.2.3")
	policies := fixturePolicies{
		local: localOnly,
		denies: map[string]contract.Decision{
			"local-hidden.home.arpa.": {Blocked: true, Reason: "manual-deny", Rule: "local-hidden"},
		},
		allows: map[string]contract.Decision{
			"public.example.": {Allowed: true, Reason: "manual-allow", Rule: "public-allow"},
		},
		blocks: map[string]contract.Decision{
			"blocked.example.": {Blocked: true, Reason: "service-block", Rule: "fixture"},
		},
	}
	local := fixtureLocal{
		"alias.home.arpa.": {
			Found: true, Answer: []dns.RR{
				rr(t, "alias.home.arpa. 60 IN CNAME device.home.arpa."),
				rr(t, "device.home.arpa. 60 IN A 192.0.2.9"),
			},
		},
		"public-alias.home.arpa.": {
			Found: true, PublicTarget: "public.example.",
			Answer: []dns.RR{rr(t, "public-alias.home.arpa. 60 IN CNAME public.example.")},
		},
		"local-hidden.home.arpa.": {
			Found: true, Answer: []dns.RR{rr(t, "local-hidden.home.arpa. 60 IN AAAA 2001:db8::9")},
		},
	}
	upstream := &fixtureUpstream{records: []dns.RR{rr(t, "public.example. 60 IN A 192.0.2.4")}}
	view := &contract.View{Policies: policies, Local: local, Upstream: upstream}
	run := func(peer netip.Addr, name string) answer {
		t.Helper()
		query := new(dns.Msg).SetQuestion(name, dns.TypeA).SetEdns0(1232, true)
		_, result := evaluate(context.Background(), view, contract.Input{
			Name: name, Peer: peer, Type: dns.TypeA, Class: dns.ClassINET, Recursion: true, EDNS: true,
		}, query)
		return result
	}

	if result := run(filtered, "public.example."); result.result.RCode != dns.RcodeSuccess || result.result.Rule != "public-allow" {
		t.Fatalf("filtered client: %+v", result)
	}
	if result := run(filtered, "public.example."); result.result.Origin != "cache" {
		t.Fatalf("warm reply: %+v", result)
	}
	if result := run(localOnly, "public.example."); result.result.RCode != dns.RcodeRefused || upstream.calls.Load() != 2 {
		t.Fatalf("local-only client reached upstream/cache: %+v", result)
	}
	if result := run(localOnly, "alias.home.arpa."); result.result.Origin != "local" || len(result.message.Answer) != 2 {
		t.Fatalf("local-only client cannot resolve local chain: %+v", result)
	}
	if result := run(localOnly, "public-alias.home.arpa."); result.result.RCode != dns.RcodeRefused {
		t.Fatalf("local-only client followed public alias: %+v", result)
	}
	if result := run(filtered, "public-alias.home.arpa."); result.result.RCode != dns.RcodeSuccess ||
		len(result.message.Answer) != 2 || result.message.AuthenticatedData {
		t.Fatalf("partly synthesized public alias: %+v", result)
	}
	if result := run(filtered, "local-hidden.home.arpa."); result.result.RCode != dns.RcodeNameError || !result.extended {
		t.Fatalf("manual denial did not cover local name: %+v", result)
	}
	for _, record := range []string{
		"public.example. 60 IN CNAME blocked.example.",
		"public.example. 60 IN HTTPS 0 blocked.example.",
		"public.example. 60 IN SVCB 0 blocked.example.",
	} {
		upstream.records = []dns.RR{rr(t, record)}
		result := run(filtered, "public.example.")
		if result.result.RCode != dns.RcodeNameError || result.result.Rule != "fixture" ||
			result.result.Cache != "hit" || !result.extended {
			t.Fatalf("%s bypassed cached target checks: %+v", record, result)
		}
	}

	server := startFixture(t, "127.0.0.1:0", netip.MustParsePrefix("127.0.0.1/32"), view)
	query := new(dns.Msg).SetQuestion("blocked.example.", dns.TypeAAAA).SetEdns0(1232, false)
	blocked := exchange(t, server, "udp", query)
	if blocked.Rcode != dns.RcodeNameError || len(blocked.IsEdns0().Option) != 1 ||
		blocked.IsEdns0().Option[0].(*dns.EDNS0_EDE).InfoCode != dns.ExtendedErrorCodeBlocked {
		t.Fatalf("expected EDE Blocked: %v", blocked)
	}
}
