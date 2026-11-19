package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/config"
	"github.com/quic-go/quic-go"
)

const dnsMessageType = "application/dns-message"

type endpoint struct {
	kind      string
	host      string
	port      string
	bootstrap []netip.Addr
	resolver  *net.Resolver
	tls       *tls.Config
	url       string
	client    *http.Client
	transport *http.Transport
	idleLimit chan struct{}

	mu     sync.Mutex
	health EndpointStatus
	idle   *idleTLS
	closed bool
}

type idleTLS struct {
	conn  net.Conn
	timer *time.Timer
}

func newEndpoint(pool string, index int, cfg config.Endpoint, options Options, idleLimit chan struct{}) (*endpoint, error) {
	ep := &endpoint{
		kind: strings.ToLower(cfg.Transport), host: cfg.Address,
		bootstrap: append([]netip.Addr(nil), cfg.Bootstrap...),
		resolver:  options.BootstrapResolver,
		idleLimit: idleLimit,
	}
	serverName := strings.TrimSuffix(cfg.ServerName, ".")
	var port uint16
	switch ep.kind {
	case "dot", "doq":
		if cfg.URL != "" {
			return nil, errors.New("only DoH endpoints accept a URL")
		}
		port = 853
		if serverName == "" {
			serverName = strings.TrimSuffix(ep.host, ".")
		}
	case "doh":
		uri, err := url.Parse(cfg.URL)
		if err != nil || uri.Scheme != "https" || uri.Hostname() == "" ||
			uri.User != nil || uri.Fragment != "" || uri.Opaque != "" {
			return nil, errors.New("DoH requires an HTTPS URL without credentials or fragment")
		}
		ep.url = uri.String()
		port = 443
		if uri.Port() != "" {
			n, err := strconv.ParseUint(uri.Port(), 10, 16)
			if err != nil || n == 0 {
				return nil, errors.New("invalid DoH URL port")
			}
			port = uint16(n)
		}
		if serverName == "" {
			serverName = strings.TrimSuffix(uri.Hostname(), ".")
		}
		if ep.host == "" {
			ep.host = uri.Hostname()
		}
	default:
		return nil, errors.New("transport must be dot, doh, or doq")
	}
	if cfg.Port != 0 {
		port = cfg.Port
	}
	for _, ip := range ep.bootstrap {
		if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errors.New("invalid bootstrap address")
		}
	}
	if ep.host == "" && len(ep.bootstrap) != 0 {
		ep.host = serverName
	}
	if !validHost(ep.host) || !validHost(serverName) {
		return nil, errors.New("invalid upstream address or TLS verification name")
	}
	ep.port = strconv.Itoa(int(port))
	ep.tls = &tls.Config{ServerName: serverName, RootCAs: options.TLSRoots, MinVersion: tls.VersionTLS12}
	ep.health = EndpointStatus{Pool: pool, Index: index, Transport: ep.kind, State: "untested"}

	switch ep.kind {
	case "doh":
		ep.tls.NextProtos = []string{"h2", "http/1.1"}
		ep.transport = &http.Transport{
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				ctx, cancel := context.WithTimeout(ctx, options.Deadline)
				defer cancel()
				return dialAddress(ctx, ep, (&tls.Dialer{Config: ep.tls}).DialContext, "tcp")
			},
			TLSClientConfig:    ep.tls,
			ForceAttemptHTTP2:  true,
			DisableCompression: true,
			MaxConnsPerHost:    options.MaxConnections,
			MaxIdleConns:       1,
			IdleConnTimeout:    30 * time.Second,
		}
		ep.client = &http.Client{
			Transport: ep.transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	case "doq":
		ep.tls.MinVersion = tls.VersionTLS13
		ep.tls.NextProtos = []string{"doq"}
	}
	return ep, nil
}

func validHost(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return !ip.IsUnspecified() && !ip.IsMulticast()
	}
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func (e *endpoint) exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	if e.kind == "dot" {
		return e.exchangeTLS(ctx, query)
	}
	zeroID := *query
	zeroID.Id = 0
	if e.kind == "doh" {
		return e.exchangeHTTPS(ctx, &zeroID)
	}
	return e.exchangeQUIC(ctx, &zeroID)
}

func (e *endpoint) exchangeTLS(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	if conn := e.takeIdleTLS(); conn != nil {
		reply, err := e.dotRoundTrip(ctx, conn, query)
		if err == nil || !staleConnection(err) {
			return reply, err
		}
	}
	dialer := &tls.Dialer{Config: e.tls}
	conn, err := dialAddress(ctx, e, dialer.DialContext, "tcp")
	if err != nil {
		return nil, err
	}
	return e.dotRoundTrip(ctx, conn, query)
}

func staleConnection(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, net.ErrClosed)
}

func (e *endpoint) dotRoundTrip(ctx context.Context, conn net.Conn, query *dns.Msg) (_ *dns.Msg, err error) {
	defer func() {
		if err == nil {
			e.storeIdleTLS(conn)
		} else {
			conn.Close()
		}
	}()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		conn.Close()
		close(closed)
	})
	defer func() {
		if !stop() {
			<-closed
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	if err = writeFramed(conn, query); err != nil {
		return nil, err
	}
	reply, err := readFramed(conn)
	if err != nil {
		return nil, err
	}
	// Confirm a complete exchange before making this stream available again.
	if err = validateReply("dot", query, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func (e *endpoint) exchangeHTTPS(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	packed, err := query.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(packed))
	if err != nil {
		return nil, errors.New("invalid DoH request")
	}
	req.Header.Set("Accept", dnsMessageType)
	req.Header.Set("Content-Type", dnsMessageType)
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP status %d", resp.StatusCode)
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != dnsMessageType {
		return nil, errors.New("invalid DoH response media type")
	}
	wire, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize+1))
	if err != nil {
		return nil, err
	}
	if len(wire) > dns.MaxMsgSize {
		return nil, errors.New("DoH DNS message exceeds wire limit")
	}
	reply, err := unpack(wire)
	if err != nil {
		return nil, err
	}
	if age := resp.Header.Get("Age"); age != "" {
		seconds, err := strconv.ParseUint(strings.TrimSpace(age), 10, 64)
		if err != nil {
			return nil, errors.New("invalid DoH HTTP Age")
		}
		ageRecords(reply, uint32(min(seconds, uint64(^uint32(0)))))
	}
	return reply, nil
}

func (e *endpoint) exchangeQUIC(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	cfg := &quic.Config{MaxIncomingStreams: -1, MaxIncomingUniStreams: -1}
	dial := func(ctx context.Context, _, address string) (*quic.Conn, error) {
		return quic.DialAddr(ctx, address, e.tls, cfg)
	}
	conn, err := dialAddress(ctx, e, dial, "udp")
	if err != nil {
		return nil, err
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	if err = stream.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() {
		const requestCancelled = 3
		stream.CancelRead(requestCancelled)
		stream.CancelWrite(requestCancelled)
	})
	defer stop()
	if err = writeFramed(stream, query); err != nil {
		return nil, err
	}
	if err = stream.Close(); err != nil {
		return nil, err
	}
	reply, err := readFramed(stream)
	if err != nil {
		return nil, err
	}
	// DoQ uses exactly one length-prefixed request and reply on the stream.
	var extra [1]byte
	if n, err := io.ReadFull(stream, extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid DoQ end of response stream")
	}
	return reply, nil
}

func dialAddress[T any](ctx context.Context, ep *endpoint, dial func(context.Context, string, string) (T, error), network string) (T, error) {
	var empty T
	addresses := ep.bootstrap
	if len(addresses) == 0 {
		if ip, err := netip.ParseAddr(ep.host); err == nil {
			addresses = []netip.Addr{ip}
		} else {
			addresses, err = ep.resolver.LookupNetIP(ctx, "ip", ep.host)
			if err != nil {
				return empty, err
			}
		}
	}
	deadline, hasDeadline := ctx.Deadline()
	lastErr := errors.New("upstream hostname has no addresses")
	for i, ip := range addresses {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		attempt := ctx
		cancel := func() {}
		if hasDeadline {
			attempt, cancel = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(addresses)-i))
		}
		conn, err := dial(attempt, network, net.JoinHostPort(ip.Unmap().String(), ep.port))
		cancel()
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return empty, lastErr
}

func writeFramed(writer io.Writer, msg *dns.Msg) error {
	wire, err := msg.Pack()
	if err != nil {
		return err
	}
	if len(wire) > dns.MaxMsgSize {
		return errors.New("DNS message exceeds wire limit")
	}
	frame := make([]byte, 2, 2+len(wire))
	binary.BigEndian.PutUint16(frame, uint16(len(wire)))
	frame = append(frame, wire...)
	n, err := writer.Write(frame)
	if err == nil && n != len(frame) {
		return io.ErrShortWrite
	}
	return err
}

func readFramed(reader io.Reader) (*dns.Msg, error) {
	var size [2]byte
	if _, err := io.ReadFull(reader, size[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(size[:]))
	if length < 12 {
		return nil, errors.New("DNS wire message has no header")
	}
	wire := make([]byte, length)
	if _, err := io.ReadFull(reader, wire); err != nil {
		return nil, err
	}
	return unpack(wire)
}

func unpack(wire []byte) (*dns.Msg, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		return nil, err
	}
	return msg, nil
}

func (e *endpoint) close() {
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
	if conn := e.takeIdleTLS(); conn != nil {
		conn.Close()
	}
	if e.transport != nil {
		e.transport.CloseIdleConnections()
	}
}

func (e *endpoint) takeIdleTLS() net.Conn {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.idle == nil {
		return nil
	}
	idle := e.idle
	e.idle = nil
	idle.timer.Stop()
	<-e.idleLimit
	return idle.conn
}

func (e *endpoint) storeIdleTLS(conn net.Conn) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.idle != nil {
		conn.Close()
		return
	}
	select {
	case e.idleLimit <- struct{}{}:
	default:
		conn.Close()
		return
	}
	idle := &idleTLS{conn: conn}
	e.idle = idle
	idle.timer = time.AfterFunc(20*time.Second, func() {
		e.mu.Lock()
		if e.idle != idle {
			e.mu.Unlock()
			return
		}
		e.idle = nil
		<-e.idleLimit
		e.mu.Unlock()
		conn.Close()
	})
}

func (e *endpoint) backoff() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.health.BackoffUntil
}

func (e *endpoint) status() EndpointStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.health
}

func (e *endpoint) record(start time.Time, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.health.LastAttempt = start
	e.health.Latency = time.Since(start)
	if err == nil {
		e.health.State = "available"
		e.health.Failures = 0
		e.health.LastError = ""
		e.health.BackoffUntil = time.Time{}
		return
	}

	e.health.State = "unavailable"
	e.health.Failures++
	e.health.LastError = errorClass(err)
	e.health.BackoffUntil = time.Now().Add(time.Second << min(e.health.Failures-1, 5))
}

func errorClass(err error) string {
	var host x509.HostnameError
	var unknown x509.UnknownAuthorityError
	var certificate *tls.CertificateVerificationError
	var netErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case errors.As(err, &host):
		return "TLS name mismatch"
	case errors.As(err, &unknown), errors.As(err, &certificate):
		return "TLS certificate verification failed"
	default:
		return "encrypted exchange failed"
	}
}
