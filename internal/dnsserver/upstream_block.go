package dnsserver

import (
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// maxBlockDetail bounds the upstream-supplied text kept with a query log entry.
const maxBlockDetail = 128

// upstreamBlock reports whether a filtering upstream resolver blocked the
// query, and a short description of why. Only statistics depend on it: the
// reply is still returned to the client unchanged.
//
// An RFC 8914 Extended DNS Error of Blocked, Censored, Filtered or Prohibited
// is the strongest signal and covers every query type. NextDNS, for example,
// sends Filtered with the matching blocklist in the extra text. Resolvers that
// send no EDE are recognized by an answer whose addresses are all 0.0.0.0 or ::.
func upstreamBlock(reply *dns.Msg) (bool, string) {
	if opt := reply.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			ede, ok := option.(*dns.EDNS0_EDE)
			if !ok {
				continue
			}
			switch ede.InfoCode {
			case dns.ExtendedErrorCodeBlocked, dns.ExtendedErrorCodeCensored,
				dns.ExtendedErrorCodeFiltered, dns.ExtendedErrorCodeProhibited:
				if text := blockDetail(ede.ExtraText); text != "" {
					return true, text
				}
				name := dns.ExtendedErrorCodeToString[ede.InfoCode]
				return true, "EDE " + strconv.Itoa(int(ede.InfoCode)) + " " + name
			}
		}
	}
	addresses := 0
	for _, rr := range reply.Answer {
		switch record := rr.(type) {
		case *dns.A:
			if !record.A.IsUnspecified() {
				return false, ""
			}
			addresses++
		case *dns.AAAA:
			if !record.AAAA.IsUnspecified() {
				return false, ""
			}
			addresses++
		}
	}
	if addresses > 0 {
		return true, "Unspecified address answer"
	}
	return false, ""
}

// blockDetail keeps printable ASCII from upstream text, which is untrusted and
// ends up in the query log and the console.
func blockDetail(text string) string {
	text = strings.TrimSpace(text)
	var b strings.Builder
	for i := 0; i < len(text) && b.Len() < maxBlockDetail; i++ {
		if c := text[i]; c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
		}
	}
	return strings.TrimSpace(b.String())
}
