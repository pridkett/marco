// Package upstream exchanges DNS messages with named, encrypted resolver pools.
package upstream

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/config"
)

type Options struct {
	Deadline          time.Duration
	CacheEntries      int
	CacheTTL          time.Duration
	BootstrapResolver *net.Resolver
	TLSRoots          *x509.CertPool
	MaxConnections    int
}

type Pools struct {
	pools    map[string][]*endpoint
	names    []string
	deadline time.Duration
	limit    chan struct{}
	cache    *responseCache

	mu       sync.Mutex
	inflight map[cacheKey]*flight
}

type flight struct {
	done  chan struct{}
	reply *dns.Msg
	err   error
}

type EndpointStatus struct {
	Pool         string        `json:"pool"`
	Index        int           `json:"index"`
	Transport    string        `json:"transport"`
	State        string        `json:"state"`
	Latency      time.Duration `json:"latency"`
	Failures     int           `json:"failures"`
	LastError    string        `json:"lastError,omitempty"`
	LastAttempt  time.Time     `json:"lastAttempt,omitempty"`
	BackoffUntil time.Time     `json:"backoffUntil,omitempty"`
}

func New(configured map[string][]config.Endpoint, options Options) (*Pools, error) {
	if options.Deadline < 0 || options.CacheEntries < 0 || options.CacheTTL < 0 || options.MaxConnections < 0 {
		return nil, errors.New("negative upstream limits are invalid")
	}
	if options.Deadline == 0 {
		options.Deadline = 2 * time.Second
	}
	if options.CacheEntries == 0 {
		options.CacheEntries = 2048
	}
	if options.CacheTTL == 0 {
		options.CacheTTL = 300 * time.Second
	}
	if options.MaxConnections == 0 {
		options.MaxConnections = 32
	}
	if options.BootstrapResolver == nil {
		options.BootstrapResolver = net.DefaultResolver
	}
	if options.TLSRoots != nil {
		options.TLSRoots = options.TLSRoots.Clone()
	}

	p := &Pools{
		pools: make(map[string][]*endpoint, len(configured)), deadline: options.Deadline,
		limit:    make(chan struct{}, options.MaxConnections),
		cache:    newCache(options.CacheEntries, options.CacheTTL),
		inflight: make(map[cacheKey]*flight),
	}
	idle := make(chan struct{}, options.MaxConnections)
	for name := range configured {
		p.names = append(p.names, name)
	}
	sort.Strings(p.names)
	endpointCount := 0
	for _, name := range p.names {
		if name == "" || len(configured[name]) == 0 {
			p.Close()
			return nil, errors.New("upstream pool requires a name and at least one endpoint")
		}
		for i, item := range configured[name] {
			if endpointCount == 128 {
				p.Close()
				return nil, errors.New("configured upstream endpoints exceed the limit of 128")
			}
			endpointCount++
			ep, err := newEndpoint(name, i, item, options, idle)
			if err != nil {
				p.Close()
				return nil, fmt.Errorf("pool %q endpoint %d: %w", name, i+1, err)
			}
			p.pools[name] = append(p.pools[name], ep)
		}
	}
	return p, nil
}

func (p *Pools) Close() {
	for _, endpoints := range p.pools {
		for _, ep := range endpoints {
			ep.close()
		}
	}
}

func (p *Pools) Status() []EndpointStatus {
	var result []EndpointStatus
	for _, pool := range p.names {
		for _, ep := range p.pools[pool] {
			result = append(result, ep.status())
		}
	}
	return result
}

// Test exchanges a DNS query directly with the selected zero-based endpoint.
func (p *Pools) Test(ctx context.Context, pool string, index int) error {
	endpoints := p.pools[pool]
	if index < 0 || index >= len(endpoints) {
		return errors.New("unknown upstream endpoint")
	}
	ctx, cancel := context.WithTimeout(ctx, p.deadline)
	defer cancel()
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	_, err := p.try(ctx, endpoints[index], query)
	if err != nil {
		return errors.New(errorClass(err))
	}
	return nil
}

func (p *Pools) Exchange(ctx context.Context, pool string, request *dns.Msg) (*dns.Msg, bool, error) {
	query, cacheable, err := upstreamQuery(request)
	if err != nil {
		return nil, false, err
	}
	if pool == "" && len(p.names) == 1 {
		pool = p.names[0]
	}
	if len(p.pools[pool]) == 0 {
		return nil, false, errors.New("no configured upstream pool")
	}
	ctx, cancel := context.WithTimeout(ctx, p.deadline)
	defer cancel()
	if !cacheable {
		reply, err := p.exchange(ctx, p.pools[pool], query)
		return responseEnvelope(reply, request), false, err
	}

	key := questionKey(pool, query)
	p.mu.Lock()
	if reply := p.cache.get(key, time.Now()); reply != nil {
		p.mu.Unlock()
		return responseEnvelope(reply, request), true, nil
	}
	if f, ok := p.inflight[key]; ok {
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-f.done:
			return responseEnvelope(f.reply, request), false, f.err
		}
	}
	// Bound pending map growth for callers that use this package without the
	// LAN listener's own request limit.
	if len(p.inflight) >= 4*cap(p.limit) {
		p.mu.Unlock()
		return nil, false, errors.New("upstream request queue full")
	}
	f := &flight{done: make(chan struct{})}
	p.inflight[key] = f
	p.mu.Unlock()

	f.reply, f.err = p.exchange(ctx, p.pools[pool], query)
	entry := p.cache.prepare(f.reply, time.Now())
	p.mu.Lock()
	if entry != nil {
		p.cache.put(key, entry)
	}
	delete(p.inflight, key)
	close(f.done)
	p.mu.Unlock()
	return responseEnvelope(f.reply, request), false, f.err
}

func (p *Pools) exchange(ctx context.Context, endpoints []*endpoint, query *dns.Msg) (*dns.Msg, error) {
	now := time.Now()
	var eligible []*endpoint
	for _, ep := range endpoints {
		if blockedUntil := ep.backoff(); !blockedUntil.After(now) {
			eligible = append(eligible, ep)
		}
	}
	if len(eligible) == 0 {
		// Honor the retry interval during outages and recover on the first
		// subsequent query after at least one endpoint becomes eligible.
		return nil, errors.New("upstream endpoints are backing off")
	}
	deadline, _ := ctx.Deadline()
	for index, ep := range eligible {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		remaining := time.Until(deadline)
		attempt, cancel := context.WithTimeout(ctx, remaining/time.Duration(len(eligible)-index))
		reply, err := p.try(attempt, ep, query)
		cancel()
		if err == nil {
			return reply, nil
		}
	}
	return nil, errors.New("encrypted upstream pool exhausted")
}

func (p *Pools) try(ctx context.Context, ep *endpoint, query *dns.Msg) (*dns.Msg, error) {
	select {
	case p.limit <- struct{}{}:
		defer func() { <-p.limit }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	start := time.Now()
	reply, err := ep.exchange(ctx, query)
	if err == nil {
		err = validateReply(ep.kind, query, reply)
	}
	ep.record(start, err)
	if err != nil {
		return nil, err
	}
	clampNegativeTTL(reply)
	sanitizeReply(reply)
	return reply, nil
}

func responseEnvelope(reply, request *dns.Msg) *dns.Msg {
	if reply == nil {
		return nil
	}
	out := reply.Copy()
	out.Id = request.Id
	out.Question = append([]dns.Question(nil), request.Question...)
	out.RecursionDesired = request.RecursionDesired
	out.CheckingDisabled = request.CheckingDisabled
	return out
}

func upstreamQuery(request *dns.Msg) (*dns.Msg, bool, error) {
	if request == nil || request.Response || request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 {
		return nil, false, errors.New("unsupported upstream request")
	}
	if request.IsTsig() != nil {
		return nil, false, errors.New("TSIG forwarding is unsupported")
	}
	q := request.Question[0]
	q.Name = dns.CanonicalName(q.Name)
	query := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id: dns.Id(), RecursionDesired: true, CheckingDisabled: request.CheckingDisabled,
			AuthenticatedData: request.AuthenticatedData,
		},
		Question: []dns.Question{q},
	}
	opt := request.IsEdns0()
	if opt == nil {
		return query, true, nil
	}
	query.SetEdns0(1232, opt.Do())
	cacheable := opt.Version() == 0 && !opt.Co() && opt.Z() == 0
	upstreamOPT := query.IsEdns0()
	for _, item := range opt.Option {
		switch item.Option() {
		case dns.EDNS0SUBNET, dns.EDNS0COOKIE, dns.EDNS0PADDING, dns.EDNS0TCPKEEPALIVE:
			// These identify a client or describe the downstream hop.
		case dns.EDNS0NSID, dns.EDNS0DAU, dns.EDNS0DHU, dns.EDNS0N3U, dns.EDNS0EXPIRE:
			cacheable = false
			// Keep only understood options. An unknown option can carry
			// arbitrary client-specific data.
			upstreamOPT.Option = append(upstreamOPT.Option, item)
		default:
			cacheable = false
		}
	}
	return query, cacheable, nil
}

func validateReply(kind string, query, reply *dns.Msg) error {
	id := query.Id
	if kind == "doq" || kind == "doh" {
		id = 0
	}
	if reply == nil || !reply.Response || reply.Opcode != dns.OpcodeQuery ||
		reply.Id != id || reply.Truncated || reply.Zero || len(reply.Question) != 1 ||
		reply.IsTsig() != nil {
		return errors.New("invalid DNS response envelope")
	}
	got, want := reply.Question[0], query.Question[0]
	if dns.CanonicalName(got.Name) != want.Name || got.Qtype != want.Qtype || got.Qclass != want.Qclass {
		return errors.New("mismatched DNS question")
	}
	if reply.Rcode != dns.RcodeSuccess && reply.Rcode != dns.RcodeNameError {
		return fmt.Errorf("upstream DNS error %d", reply.Rcode)
	}
	seenOPT := false
	for _, rr := range reply.Extra {
		if opt, ok := rr.(*dns.OPT); ok {
			if seenOPT || opt.Hdr.Name != "." || opt.Version() != 0 {
				return errors.New("invalid DNS OPT response")
			}
			seenOPT = true
		}
	}
	return nil
}

func sanitizeReply(reply *dns.Msg) {
	if opt := reply.IsEdns0(); opt != nil {
		retained := opt.Option[:0]
		for _, item := range opt.Option {
			switch item.Option() {
			case dns.EDNS0EDE, dns.EDNS0NSID, dns.EDNS0EXPIRE, dns.EDNS0DAU, dns.EDNS0DHU, dns.EDNS0N3U:
				retained = append(retained, item)
			}
		}
		opt.Option = retained
	}
}
