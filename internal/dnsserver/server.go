// Package dnsserver serves LAN DNS and applies one immutable DNS view per query.
package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
)

type Options struct {
	Address     string
	Allow       []netip.Prefix
	MaxUDPSize  uint16
	Concurrency int
	Node        string
	View        func() *contract.View
	Observe     func(contract.Event)
}

type Server struct {
	handler *handler
	tcp     *dns.Server
	udp     *dns.Server
	address string
	running atomic.Int32
	cancel  context.CancelFunc
}

type handler struct {
	options Options
	slots   chan struct{}
	ctx     context.Context
}

// Listen activates UDP and TCP on the same address. It closes any partial bind
// before returning an error.
func Listen(options Options) (*Server, error) {
	if options.View == nil || options.Address == "" || len(options.Allow) == 0 {
		return nil, errors.New("DNS requires an address, source CIDRs, and a view")
	}
	for _, prefix := range options.Allow {
		if !prefix.IsValid() || prefix.Addr().Is4In6() {
			return nil, errors.New("invalid DNS source CIDR")
		}
	}
	options.Allow = append([]netip.Prefix(nil), options.Allow...)
	if options.MaxUDPSize == 0 {
		options.MaxUDPSize = 1232
	}
	if options.MaxUDPSize < dns.MinMsgSize {
		return nil, errors.New("maximum UDP size must be at least 512")
	}
	if options.Concurrency == 0 {
		options.Concurrency = 128
	}
	if options.Concurrency < 0 {
		return nil, errors.New("DNS concurrency must be positive")
	}
	tcp, err := net.Listen("tcp", options.Address)
	if err != nil {
		return nil, fmt.Errorf("bind TCP DNS: %w", err)
	}
	addr := tcp.Addr().String()
	udp, err := net.ListenPacket("udp", addr)
	if err != nil {
		tcp.Close()
		return nil, fmt.Errorf("bind UDP DNS: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &handler{options: options, slots: make(chan struct{}, options.Concurrency), ctx: ctx}
	s := &Server{handler: h, address: addr, cancel: cancel}
	accept := func(header dns.Header) dns.MsgAcceptAction {
		if header.Bits&(1<<15) != 0 {
			return dns.MsgIgnore
		}
		return dns.MsgAccept
	}
	s.tcp = &dns.Server{
		Listener: &restrictedListener{Listener: tcp, admits: h.admits, slots: make(chan struct{}, options.Concurrency)},
		Handler:  h, MsgAcceptFunc: accept,
	}
	s.udp = &dns.Server{
		PacketConn: udp, Handler: h, MsgAcceptFunc: accept, UDPSize: int(options.MaxUDPSize),
		DecorateReader: func(reader dns.Reader) dns.Reader {
			return &restrictedReader{Reader: reader, handler: h}
		},
	}

	tcpStarted, udpStarted := s.activate(s.tcp), s.activate(s.udp)
	if tcpErr, udpErr := <-tcpStarted, <-udpStarted; tcpErr != nil || udpErr != nil {
		_ = s.Shutdown(context.Background())
		tcp.Close()
		udp.Close()
		return nil, errors.Join(tcpErr, udpErr)
	}
	return s, nil
}

func (s *Server) activate(protocol *dns.Server) <-chan error {
	started := make(chan error, 1)
	active := false
	protocol.NotifyStartedFunc = func() {
		active = true
		s.running.Add(1)
		started <- nil
	}
	go func() {
		err := protocol.ActivateAndServe()
		if active {
			s.running.Add(-1)
			return
		}
		if err == nil {
			err = errors.New("DNS listener stopped before startup")
		}
		started <- err
	}()
	return started
}

func (s *Server) Address() string { return s.address }

func (s *Server) Ready() bool {
	return s.running.Load() == 2 && s.handler.ctx.Err() == nil && s.handler.options.View() != nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.cancel()
	tcp := make(chan error, 1)
	go func() { tcp <- s.tcp.ShutdownContext(ctx) }()
	udpErr := s.udp.ShutdownContext(ctx)
	return errors.Join(<-tcp, udpErr)
}

func (h *handler) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	peer := peerIP(w.RemoteAddr())
	if !h.admits(peer) {
		return
	}
	now := time.Now()
	in := contract.Input{
		Peer: peer, Time: now, Recursion: request.RecursionDesired,
		CheckingDisabled: request.CheckingDisabled,
	}
	if len(request.Question) == 1 {
		q := request.Question[0]
		in.Name, in.Type, in.Class = dns.CanonicalName(q.Name), q.Qtype, q.Qclass
	}
	opt, invalidExtra := requestOPT(request)
	if opt != nil {
		in.EDNS, in.DNSSEC = true, opt.Do()
	}
	var selected contract.Selection
	var response answer
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
		switch {
		case request.Opcode == dns.OpcodeUpdate || in.Type == dns.TypeAXFR || in.Type == dns.TypeIXFR:
			response = outcome(dns.RcodeRefused, "server", "unsupported-operation")
		case request.Opcode != dns.OpcodeQuery:
			response = outcome(dns.RcodeNotImplemented, "server", "unsupported-operation")
		case request.IsTsig() != nil || in.Type == dns.TypeTSIG || in.Type == dns.TypeTKEY:
			response = outcome(dns.RcodeNotImplemented, "server", "unsupported-tsig")
		case len(request.Question) != 1 || in.Type == 0 || request.Zero || len(request.Answer) != 0 || len(request.Ns) != 0 || invalidExtra:
			response = outcome(dns.RcodeFormatError, "server", "malformed-query")
		case opt != nil && opt.Version() != 0:
			response = outcome(dns.RcodeBadVers, "server", "unsupported-edns-version")
		case in.Class != dns.ClassINET:
			response = outcome(dns.RcodeNotImplemented, "server", "unsupported-class")
		default:
			selected, response = evaluate(h.ctx, h.options.View(), in, request)
		}
	default:
		response = outcome(dns.RcodeServerFailure, "server", "overloaded")
	}

	reply := response.message
	if reply == nil {
		reply = new(dns.Msg)
	}
	reply.Id = request.Id
	reply.Opcode = request.Opcode
	reply.Response = true
	if len(request.Question) == 1 {
		reply.Question = request.Question
	}
	reply.Rcode = response.result.RCode
	reply.RecursionDesired = request.RecursionDesired
	reply.RecursionAvailable = selected.Policy.Mode == config.Filtered || selected.Policy.Mode == config.Unfiltered
	reply.CheckingDisabled = request.CheckingDisabled
	reply.Compress = true
	limit := h.envelope(w.RemoteAddr(), reply, opt, response.extended)
	reply.Truncate(limit)
	_ = w.WriteMsg(reply)
	if h.options.Observe != nil {
		h.options.Observe(contract.Event{Input: in, Result: response.result, Node: h.options.Node, Latency: time.Since(now)})
	}
}

func requestOPT(request *dns.Msg) (*dns.OPT, bool) {
	if len(request.Extra) == 0 {
		return nil, false
	}
	if len(request.Extra) == 1 {
		opt, ok := request.Extra[0].(*dns.OPT)
		if ok && opt.Hdr.Name == "." && opt.ExtendedRcode() == 0 {
			return opt, false
		}
	}
	return nil, true
}

func (h *handler) envelope(addr net.Addr, reply *dns.Msg, requestOPT *dns.OPT, ede bool) int {
	udpSize := uint16(dns.MinMsgSize)
	if requestOPT != nil {
		udpSize = min(max(udpSize, requestOPT.UDPSize()), h.options.MaxUDPSize)
	}
	limit := dns.MaxMsgSize
	if _, udp := addr.(*net.UDPAddr); udp {
		limit = int(udpSize)
	}
	if requestOPT == nil {
		extra := reply.Extra[:0]
		for _, rr := range reply.Extra {
			if rr.Header().Rrtype != dns.TypeOPT {
				extra = append(extra, rr)
			}
		}
		reply.Extra = extra
	} else {
		opt := reply.IsEdns0()
		if opt == nil {
			reply.SetEdns0(udpSize, requestOPT.Do())
			opt = reply.IsEdns0()
		}
		opt.SetUDPSize(h.options.MaxUDPSize)
		opt.SetDo(requestOPT.Do())
		if ede {
			opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeBlocked})
		}
		// Truncate preserves OPT itself, so handle a large upstream option
		// before asking the wire library to trim ordinary records.
		skeleton := dns.Msg{Question: reply.Question, Extra: []dns.RR{opt}}
		if skeleton.Len() > limit {
			opt.Option = nil
			reply.Truncated = true
		}
	}
	return limit
}

func (h *handler) admits(ip netip.Addr) bool {
	for _, prefix := range h.options.Allow {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func peerIP(addr net.Addr) netip.Addr {
	switch typed := addr.(type) {
	case *net.UDPAddr:
		return typed.AddrPort().Addr().Unmap().WithZone("")
	case *net.TCPAddr:
		return typed.AddrPort().Addr().Unmap().WithZone("")
	}
	return netip.Addr{}
}

type restrictedReader struct {
	dns.Reader
	handler *handler
}

func (r *restrictedReader) ReadUDP(conn *net.UDPConn, timeout time.Duration) ([]byte, *dns.SessionUDP, error) {
	packet, session, err := r.Reader.ReadUDP(conn, timeout)
	if err == nil && (!r.handler.admits(peerIP(session.RemoteAddr())) || len(r.handler.slots) == cap(r.handler.slots)) {
		// A zero-length packet tells the wire server to recycle the buffer
		// without attempting to parse or answer the packet.
		packet = packet[:0]
	}
	return packet, session, err
}

type restrictedListener struct {
	net.Listener
	admits func(netip.Addr) bool
	slots  chan struct{}
}

func (l *restrictedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.admits(peerIP(conn.RemoteAddr())) {
			select {
			case l.slots <- struct{}{}:
				return &limitedConn{Conn: conn, slots: l.slots}, nil
			default:
			}
		}
		conn.Close()
	}
}

type limitedConn struct {
	net.Conn
	slots chan struct{}
	once  sync.Once
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.slots })
	return err
}
