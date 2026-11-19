package upstream

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/config"
	"github.com/quic-go/quic-go"
)

const fixtureName = "resolver.fixture.example"

var loopback = netip.MustParseAddr("127.0.0.1")

func certificates(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{fixtureName},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, roots
}

func dotFixture(t *testing.T, cert tls.Certificate, serve func(*dns.Msg) *dns.Msg) config.Endpoint {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	started := make(chan struct{})
	server := &dns.Server{
		Listener: tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{cert}}),
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
			if reply := serve(m); reply != nil {
				if err := w.WriteMsg(reply); err != nil {
					t.Error(err)
				}
			}
		}),
		NotifyStartedFunc: func() { close(started) },
	}
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := server.ShutdownContext(ctx); err != nil {
			t.Error(err)
		}
	})
	return config.Endpoint{
		Transport: "dot", Port: port, Address: "unresolvable.invalid",
		ServerName: fixtureName, Bootstrap: []netip.Addr{loopback},
	}
}

func query(name string, kind uint16) *dns.Msg {
	return new(dns.Msg).SetQuestion(name, kind)
}

func success(m *dns.Msg) *dns.Msg {
	reply := new(dns.Msg).SetReply(m)
	header := dns.RR_Header{Name: m.Question[0].Name, Class: dns.ClassINET, Ttl: 600}
	if m.Question[0].Qtype == dns.TypeAAAA {
		header.Rrtype = dns.TypeAAAA
		reply.Answer = []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.ParseIP("2001:db8::10")}}
	} else {
		header.Rrtype = dns.TypeA
		reply.Answer = []dns.RR{&dns.A{Hdr: header, A: net.ParseIP("192.0.2.10")}}
	}
	return reply
}

func negative(m *dns.Msg, rcode int) *dns.Msg {
	reply := new(dns.Msg).SetRcode(m, rcode)
	reply.Ns = []dns.RR{&dns.SOA{
		Hdr: dns.RR_Header{Name: "example.", Class: dns.ClassINET, Ttl: 50, Rrtype: dns.TypeSOA},
		Ns:  "ns.example.", Mbox: "hostmaster.example.", Minttl: 20,
	}}
	return reply
}

func makePools(t *testing.T, configured map[string][]config.Endpoint, options Options) *Pools {
	t.Helper()
	pools, err := New(configured, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pools.Close)
	return pools
}

func TestDOTFailoverAndTerminalNegative(t *testing.T) {
	cert, roots := certificates(t)
	var fallbackCalls atomic.Int64
	fallback := dotFixture(t, cert, func(query *dns.Msg) *dns.Msg {
		fallbackCalls.Add(1)
		return success(query)
	})
	mismatch := fallback
	mismatch.ServerName = "wrong.fixture.example"

	closedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachable := fallback
	unreachable.Port = uint16(closedListener.Addr().(*net.TCPAddr).Port)
	closedListener.Close()

	invalid := dotFixture(t, cert, func(query *dns.Msg) *dns.Msg {
		reply := success(query)
		reply.Question[0].Name = "wrong.example."
		return reply
	})
	terminal := dotFixture(t, cert, func(query *dns.Msg) *dns.Msg {
		if query.Question[0].Qtype == dns.TypeAAAA {
			return negative(query, dns.RcodeSuccess)
		}
		return negative(query, dns.RcodeNameError)
	})
	pools := makePools(t, map[string][]config.Endpoint{
		"lan":    {unreachable, mismatch, invalid, terminal, fallback},
		"outage": {unreachable, mismatch},
	}, Options{TLSRoots: roots})
	for _, tc := range []struct {
		kind  uint16
		rcode int
	}{
		{dns.TypeA, dns.RcodeNameError}, {dns.TypeAAAA, dns.RcodeSuccess},
	} {
		request := query("Missing.Fixture.Example.", tc.kind)
		reply, hit, err := pools.Exchange(context.Background(), "lan", request)
		if err != nil || hit || reply.Rcode != tc.rcode || len(reply.Answer) != 0 ||
			len(reply.Ns) != 1 || reply.Question[0] != request.Question[0] {
			t.Fatalf("unexpected terminal reply: hit=%v err=%v reply=%v", hit, err, reply)
		}
		request.Id = 55
		reply, hit, err = pools.Exchange(context.Background(), "lan", request)
		if err != nil || !hit || reply.Rcode != tc.rcode || reply.Id != 55 || reply.Ns[0].Header().Ttl > 20 {
			t.Fatalf("unexpected cached negative: hit=%v err=%v reply=%v", hit, err, reply)
		}
	}
	if fallbackCalls.Load() != 0 {
		t.Fatalf("terminal negatives fell through to a fallback: %d", fallbackCalls.Load())
	}
	status := pools.Status()
	if status[0].State != "unavailable" || status[1].LastError != "TLS name mismatch" ||
		status[2].State != "unavailable" || status[3].State != "available" || status[4].State != "untested" {
		t.Fatalf("unexpected endpoint health: %+v", status)
	}
	if reply, _, err := pools.Exchange(context.Background(), "outage", query("x.example.", dns.TypeA)); err == nil || reply != nil {
		t.Fatalf("encrypted outage did not fail closed: %v %v", reply, err)
	}
}

func TestDOTTimeoutKeepsOverallFailoverBudget(t *testing.T) {
	cert, roots := certificates(t)
	stall, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stall.Close()
	fallback := dotFixture(t, cert, success)
	first := fallback
	first.Port = uint16(stall.Addr().(*net.TCPAddr).Port)
	pools := makePools(t, map[string][]config.Endpoint{"lan": {first, fallback}},
		Options{TLSRoots: roots, Deadline: 600 * time.Millisecond})
	reply, _, err := pools.Exchange(context.Background(), "lan", query("ok.example.", dns.TypeA))
	if err != nil || len(reply.Answer) != 1 {
		t.Fatalf("first attempt consumed fallback budget: %v %v", reply, err)
	}
	if got := pools.Status()[0].LastError; got != "timeout" {
		t.Fatalf("expected timeout health, got %q", got)
	}
}

func TestCacheKeysAndClientEDNSSanitization(t *testing.T) {
	cert, roots := certificates(t)
	forwarded := make(chan *dns.Msg, 12)
	ep := dotFixture(t, cert, func(m *dns.Msg) *dns.Msg {
		forwarded <- m.Copy()
		reply := success(m)
		reply.AuthenticatedData = !m.CheckingDisabled
		return reply
	})
	pools := makePools(t, map[string][]config.Endpoint{"one": {ep}, "two": {ep}}, Options{TLSRoots: roots})
	request := query("Cache.Fixture.Example.", dns.TypeA).SetEdns0(4096, true)
	request.IsEdns0().Option = []dns.EDNS0{
		&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("192.0.2.5").To4()},
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0102030405060708"},
	}
	first, hit, err := pools.Exchange(context.Background(), "one", request)
	if err != nil || hit || first.Id != request.Id || !first.AuthenticatedData {
		t.Fatalf("first reply: %v %v %v", first, hit, err)
	}
	select {
	case got := <-forwarded:
		if got.Question[0].Name != "cache.fixture.example." || len(got.IsEdns0().Option) != 0 ||
			!got.IsEdns0().Do() || got.IsEdns0().UDPSize() != 1232 {
			t.Fatalf("query not sanitized: %v", got)
		}
	default:
		t.Fatal("no query forwarded")
	}
	request.Id = 500
	request.Question[0].Name = "cACHE.Fixture.Example."
	request.IsEdns0().Option = nil
	reply, hit, err := pools.Exchange(context.Background(), "one", request)
	if err != nil || !hit || reply.Id != 500 || reply.Question[0] != request.Question[0] ||
		reply.Answer[0].Header().Ttl != 300 || !reply.AuthenticatedData {
		t.Fatalf("cache envelope: %v %v %v", reply, hit, err)
	}
	for _, tc := range []struct {
		pool   string
		change func(*dns.Msg)
	}{
		{"two", func(*dns.Msg) {}},
		{"one", func(m *dns.Msg) { m.CheckingDisabled = true }},
		{"one", func(m *dns.Msg) { m.AuthenticatedData = true }},
		{"one", func(m *dns.Msg) { m.IsEdns0().SetDo(false) }},
		{"one", func(m *dns.Msg) { m.Question[0].Qtype = dns.TypeAAAA }},
		{"one", func(m *dns.Msg) { m.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_NSID{Code: dns.EDNS0NSID}} }},
	} {
		m := request.Copy()
		tc.change(m)
		if _, hit, err := pools.Exchange(context.Background(), tc.pool, m); err != nil || hit {
			t.Fatalf("differing semantics hit cache: %v %v", hit, err)
		}
	}
	if len(forwarded) != 6 {
		t.Fatalf("cache leaked across semantics: %d exchanges", len(forwarded))
	}
}

func TestCompatibleMissesCoalesce(t *testing.T) {
	cert, roots := certificates(t)
	var calls atomic.Int64
	ep := dotFixture(t, cert, func(m *dns.Msg) *dns.Msg {
		calls.Add(1)
		time.Sleep(30 * time.Millisecond)
		return success(m)
	})
	pools := makePools(t, map[string][]config.Endpoint{"lan": {ep}}, Options{TLSRoots: roots})
	start := make(chan struct{})
	var wg sync.WaitGroup
	for id := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			m := query("coalesce.example.", dns.TypeA)
			m.Id = uint16(id)
			reply, _, err := pools.Exchange(context.Background(), "lan", m)
			if err != nil || reply.Id != m.Id {
				t.Errorf("coalesced answer changed transaction ID: %v %v", reply, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("forwarded %d identical misses", calls.Load())
	}
}

func TestCacheExpiryAndNegativeSOA(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := newCache(1, 300*time.Second)
	request := query("missing.example.", dns.TypeA)
	key := questionKey("pool", request)
	empty := new(dns.Msg).SetRcode(request, dns.RcodeNameError)
	if entry := cache.prepare(empty, now); entry != nil {
		t.Fatal("cached a negative without an SOA")
	}
	msg := negative(request, dns.RcodeNameError)
	soa := msg.Ns[0].(*dns.SOA)
	soa.Hdr.Name = "unrelated.test."
	if entry := cache.prepare(msg, now); entry != nil {
		t.Fatal("cached a negative with an unrelated SOA")
	}
	soa.Hdr.Name = "example."
	cache.put(key, cache.prepare(msg, now))
	if reply := cache.get(key, now.Add(4*time.Second)); reply == nil || reply.Ns[0].Header().Ttl != 16 {
		t.Fatalf("not aging negative TTL correctly: %v", reply)
	}
	if reply := cache.get(key, now.Add(20*time.Second)); reply != nil {
		t.Fatalf("served expired negative: %v", reply)
	}
	cache.put(key, cache.prepare(success(request), now))
	otherRequest := query("other.example.", dns.TypeA)
	other := questionKey("pool", otherRequest)
	cache.put(other, cache.prepare(success(otherRequest), now))
	if cache.get(key, now) != nil || cache.get(other, now) == nil {
		t.Fatal("bounded cache did not evict oldest entry")
	}
}

func TestDoHVerifiedPostAndHTTPAge(t *testing.T) {
	cert, roots := certificates(t)
	requestWasValid := make(chan bool, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		m := new(dns.Msg)
		if err != nil || m.Unpack(body) != nil {
			http.Error(w, "invalid DNS message", http.StatusBadRequest)
			return
		}
		if m.Question[0].Name == "retry.example." {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		requestWasValid <- r.Method == "POST" && r.URL.Path == "/provider/profile" && r.URL.Query().Get("mode") == "dns" &&
			r.Header.Get("Content-Type") == dnsMessageType && r.Header.Get("Accept") == dnsMessageType &&
			r.TLS.ServerName == fixtureName && r.Host == fixtureName && r.ProtoMajor == 2 && m.Id == 0
		w.Header().Set("Content-Type", dnsMessageType)
		w.Header().Set("Age", "275")
		reply, err := success(m).Pack()
		if err != nil {
			t.Error(err)
		}
		_, _ = w.Write(reply)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	port := uint16(server.Listener.Addr().(*net.TCPAddr).Port)
	endpoint := config.Endpoint{
		Transport: "doh", URL: "https://" + fixtureName + "/provider/profile?mode=dns",
		Port: port, Bootstrap: []netip.Addr{loopback},
	}
	fallback := dotFixture(t, cert, success)
	pools := makePools(t, map[string][]config.Endpoint{"doh": {endpoint, fallback}}, Options{TLSRoots: roots})
	original := query("DoH.Example.", dns.TypeA)
	reply, _, err := pools.Exchange(context.Background(), "doh", original)
	if err != nil || reply.Id != original.Id || reply.Answer[0].Header().Ttl != 325 || !<-requestWasValid {
		t.Fatalf("unexpected verified DoH exchange: %v %v", reply, err)
	}
	reply, _, err = pools.Exchange(context.Background(), "doh", query("retry.example.", dns.TypeA))
	if err != nil || len(reply.Answer) != 1 || pools.Status()[0].State != "unavailable" {
		t.Fatalf("retryable HTTP status did not fail over: %v %v", reply, err)
	}
}

func TestDoQVerifiedFramingAndStreamTermination(t *testing.T) {
	cert, roots := certificates(t)
	listener, err := quic.ListenAddr("127.0.0.1:0",
		&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"doq"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	outcome := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		outcome <- serveDoQ(ctx, listener)
	}()

	address := listener.Addr().(*net.UDPAddr)
	ep := config.Endpoint{
		Transport: "doq", Port: uint16(address.Port), ServerName: fixtureName,
		Bootstrap: []netip.Addr{loopback},
	}
	pools := makePools(t, map[string][]config.Endpoint{"quic": {ep}}, Options{TLSRoots: roots})
	request := query("DoQ.Example.", dns.TypeA)
	reply, _, err := pools.Exchange(context.Background(), "quic", request)
	if err != nil || reply.Id != request.Id || len(reply.Answer) != 1 || reply.Question[0] != request.Question[0] {
		t.Fatalf("unexpected verified DoQ exchange: %v %v", reply, err)
	}
	if err := <-outcome; err != nil {
		t.Fatal(err)
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		outcome <- serveDoQ(ctx, listener)
	}()
	reply, _, err = pools.Exchange(context.Background(), "quic", query("extra.example.", dns.TypeA))
	if err == nil || reply != nil {
		t.Fatalf("accepted extra data on DoQ stream: %v %v", reply, err)
	}
	if err := <-outcome; err != nil {
		t.Fatal(err)
	}
}

func serveDoQ(ctx context.Context, listener *quic.Listener) error {
	conn, err := listener.Accept(ctx)
	if err != nil {
		return err
	}
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	if err := stream.SetDeadline(deadline); err != nil {
		return err
	}
	m, err := readFramed(stream)
	if err != nil {
		return err
	}
	if m.Id != 0 || conn.ConnectionState().TLS.NegotiatedProtocol != "doq" ||
		conn.ConnectionState().TLS.ServerName != fixtureName {
		return errors.New("invalid DoQ DNS ID, SNI or ALPN")
	}
	var extra [1]byte
	if n, err := io.ReadFull(stream, extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return errors.New("client did not close its write side after one message")
	}
	if err := writeFramed(stream, success(m)); err != nil {
		return err
	}
	if m.Question[0].Name == "extra.example." {
		if _, err := stream.Write([]byte{0}); err != nil {
			return err
		}
	}
	return stream.Close()
}
