package upstream

import (
	"context"
	"net"

	"github.com/miekg/dns"
)

const upstreamUDPSize = 1232

func (e *endpoint) exchangePlain(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	dialer := new(net.Dialer)
	conn, err := dialAddress(ctx, e, dialer.DialContext, e.kind)
	if err != nil {
		return nil, err
	}
	address := conn.RemoteAddr().String()
	reply, err := plainRoundTrip(ctx, conn, query)
	if err != nil || e.kind != "udp" || !reply.Truncated {
		return reply, err
	}
	if err := validateReplyQuestion(e.kind, query, reply); err != nil {
		return nil, err
	}
	conn, err = dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	return plainRoundTrip(ctx, conn, query)
}

func plainRoundTrip(ctx context.Context, conn net.Conn, query *dns.Msg) (*dns.Msg, error) {
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	dnsConn := dns.Conn{Conn: conn, UDPSize: upstreamUDPSize}
	if err := dnsConn.WriteMsg(query); err != nil {
		return nil, err
	}
	reply, err := dnsConn.ReadMsg()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return reply, err
}
