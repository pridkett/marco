package main

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/dnsserver"
	"github.com/pridkett/marco/internal/runtime"
	"github.com/pridkett/marco/internal/store"
)

func TestConditionalForwarding(t *testing.T) {
	ctx := t.Context()
	regular := startPlainResolver(t, "192.0.2.10", false)
	tail := startPlainResolver(t, "192.0.2.20", true)
	d := config.Defaults()
	d.Default.Pool = "tail"
	d.Default.Rules = []config.Rule{{Name: "blocked.tail.test"}}
	d.Assignments = []config.Assignment{{Prefix: netip.MustParsePrefix("127.0.0.1/32"), Policy: config.Policy{Pool: "regular"}}}
	d.Pools = map[string][]config.Endpoint{"regular": {regular.endpoint}, "tail": {tail.endpoint}}
	d.Forwarding = map[string]string{"Tail.TEST": "tail", "nested.tail.test.": "regular"}
	d.Zones = []config.Zone{{Name: "private.tail.test", Private: true}}
	d.Records = []config.Record{
		{Name: "local.tail.test", Type: "A", Value: "192.0.2.30"},
		{Name: "alias.test", Type: "CNAME", Value: "device.tail.test", Public: true},
	}
	db, err := store.Open(ctx, t.TempDir(), d)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	compiler, err := newCompiler(config.Deployment{})
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := runtime.Open(ctx, db, compiler)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	server, err := dnsserver.Listen(dnsserver.Options{
		Address: "127.0.0.1:0", Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, View: publisher.View,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)
	client := dns.Client{Net: "udp", Timeout: 3 * time.Second}
	ask := func(name string, recursive bool, code int) *dns.Msg {
		t.Helper()
		request := new(dns.Msg).SetQuestion(name, dns.TypeA)
		request.RecursionDesired = recursive
		reply, _, err := client.Exchange(request, server.Address())
		if err != nil || reply.Rcode != code || reply.Id != request.Id || reply.Question[0] != request.Question[0] {
			t.Fatalf("query %s: want rcode %d, got %v, %v", name, code, reply, err)
		}
		return reply
	}
	assertIP := func(name, ip string) *dns.Msg {
		t.Helper()
		reply := ask(name, true, dns.RcodeSuccess)
		if len(reply.Answer) == 0 {
			t.Fatalf("query %s returned no answers", name)
		}
		if rr, ok := reply.Answer[len(reply.Answer)-1].(*dns.A); !ok || rr.A.String() != ip {
			t.Fatalf("query %s: want %s, got %v", name, ip, reply.Answer)
		}
		return reply
	}

	assertIP("tail.test.", "192.0.2.20")
	assertIP("device.TAIL.test.", "192.0.2.20")
	if reply := assertIP("alias.test.", "192.0.2.20"); len(reply.Answer) != 2 || reply.Answer[0].Header().Rrtype != dns.TypeCNAME {
		t.Fatalf("local alias chain lost: %v", reply.Answer)
	}
	assertIP("large.tail.test.", "192.0.2.20")
	assertIP("device.nested.tail.test.", "192.0.2.10")
	assertIP("nottail.test.", "192.0.2.10")
	assertIP(`escaped\.tail.test.`, "192.0.2.10")
	assertIP("local.tail.test.", "192.0.2.30")
	ask("missing.private.tail.test.", true, dns.RcodeNameError)
	ask("blocked.tail.test.", true, dns.RcodeNameError)
	ask("uncached.tail.test.", false, dns.RcodeRefused)
	if regular.tcp.Load() != 3 || tail.udp.Load() != 3 || tail.tcp.Load() != 1 {
		t.Fatalf("unexpected upstream traffic: regular TCP=%d tail UDP=%d TCP=%d", regular.tcp.Load(), tail.udp.Load(), tail.tcp.Load())
	}

	// A truncated UDP response for a different question cannot trigger TCP retry
	// or send a tailnet name to the regular resolver.
	ask("invalid.tail.test.", true, dns.RcodeServerFailure)
	if regular.tcp.Load() != 3 || tail.udp.Load() != 4 || tail.tcp.Load() != 1 {
		t.Fatal("invalid conditional reply caused unexpected fallback")
	}
	base := publisher.Revision()
	_, err = publisher.Update(ctx, base, func(s *config.State) error {
		s.Desired.Forwarding = map[string]string{"tail.test": "missing"}
		return nil
	})
	if err == nil || publisher.Revision() != base {
		t.Fatalf("invalid route published: revision %d, error %v", publisher.Revision(), err)
	}
	assertIP("device.tail.test.", "192.0.2.20")
	_, err = publisher.Update(ctx, base, func(s *config.State) error {
		s.Desired.Forwarding = map[string]string{"tail.test": "regular"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assertIP("device.tail.test.", "192.0.2.10")
	_, err = publisher.Update(ctx, publisher.Revision(), func(s *config.State) error {
		s.Desired.Assignments[0].Policy.Mode = config.LocalOnly
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ask("device.tail.test.", true, dns.RcodeRefused)
}

func TestCompileForwardingValidation(t *testing.T) {
	d := config.Desired{Pools: map[string][]config.Endpoint{"resolver": {{Transport: "udp", Address: "192.0.2.53"}}}}
	for _, tc := range []struct {
		name  string
		input map[string]string
		want  string
	}{
		{"wildcard", map[string]string{"*.test": "resolver"}, "invalid DNS name"},
		{"root", map[string]string{".": "resolver"}, "invalid DNS name"},
		{"duplicate", map[string]string{"Tail.test": "resolver", "tail.test.": "resolver"}, "duplicate forwarding suffix"},
		{"missing pool", map[string]string{"tail.test": "missing"}, "unknown upstream pool"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d.Forwarding = tc.input
			if _, err := compileForwarding(d); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

type plainResolver struct {
	endpoint config.Endpoint
	udp, tcp atomic.Int64
}

func startPlainResolver(t *testing.T, answer string, udp bool) *plainResolver {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	resolver := &plainResolver{endpoint: config.Endpoint{
		Transport: "tcp", Address: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port),
	}}
	start := func(s *dns.Server, serve func(*dns.Msg) *dns.Msg) {
		t.Helper()
		started := make(chan struct{})
		s.NotifyStartedFunc = func() { close(started) }
		s.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
			if err := w.WriteMsg(serve(query)); err != nil {
				t.Error(err)
			}
		})
		go func() { _ = s.ActivateAndServe() }()
		<-started
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := s.ShutdownContext(ctx); err != nil {
				t.Error(err)
			}
		})
	}
	respond := func(query *dns.Msg) *dns.Msg {
		reply := new(dns.Msg).SetReply(query)
		reply.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(answer),
		}}
		return reply
	}
	start(&dns.Server{Listener: listener}, func(query *dns.Msg) *dns.Msg {
		resolver.tcp.Add(1)
		return respond(query)
	})
	if udp {
		packet, err := net.ListenPacket("udp4", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		resolver.endpoint.Transport = "udp"
		start(&dns.Server{PacketConn: packet}, func(query *dns.Msg) *dns.Msg {
			resolver.udp.Add(1)
			switch query.Question[0].Name {
			case "large.tail.test.":
				reply := new(dns.Msg).SetReply(query)
				reply.Truncated = true
				return reply
			case "invalid.tail.test.":
				reply := new(dns.Msg).SetReply(query)
				reply.Truncated = true
				reply.Question[0].Name = "different.test."
				return reply
			}
			return respond(query)
		})
	}
	return resolver
}
