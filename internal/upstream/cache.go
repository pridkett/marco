package upstream

import (
	"container/list"
	"time"

	"github.com/miekg/dns"
)

type cacheKey struct {
	pool     string
	question dns.Question
	flags    uint8
}

func questionKey(pool string, query *dns.Msg) cacheKey {
	var flags uint8
	if query.CheckingDisabled {
		flags |= 1
	}
	if query.AuthenticatedData {
		flags |= 2
	}
	if opt := query.IsEdns0(); opt != nil {
		flags |= 4
		if opt.Do() {
			flags |= 8
		}
	}
	return cacheKey{pool: pool, question: query.Question[0], flags: flags}
}

// A byte limit complements the entry limit because wire responses can range
// from a few dozen bytes to nearly 64 KiB. Access is serialized by Pools.mu.
const cacheByteLimit = 4 << 20

type responseCache struct {
	entries map[cacheKey]*list.Element
	order   list.List
	limit   int
	ceiling uint32
	bytes   int
}

type cacheEntry struct {
	key     cacheKey
	wire    []byte
	stored  time.Time
	expires time.Time
}

func newCache(limit int, ceiling time.Duration) *responseCache {
	return &responseCache{
		entries: make(map[cacheKey]*list.Element), limit: limit,
		ceiling: uint32(min(ceiling/time.Second, time.Duration(^uint32(0)))),
	}
}

func (c *responseCache) get(key cacheKey, now time.Time) *dns.Msg {
	item := c.entries[key]
	if item == nil {
		return nil
	}
	entry := item.Value.(*cacheEntry)
	if !now.Before(entry.expires) {
		c.remove(item)
		return nil
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(entry.wire); err != nil {
		c.remove(item)
		return nil
	}
	c.order.MoveToFront(item)
	ageRecords(msg, uint32(now.Sub(entry.stored)/time.Second))
	return msg
}

func ageRecords(msg *dns.Msg, elapsed uint32) {
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			h := rr.Header()
			if h.Rrtype != dns.TypeOPT {
				h.Ttl -= min(h.Ttl, elapsed)
			}
		}
	}
}

func (c *responseCache) prepare(message *dns.Msg, now time.Time) *cacheEntry {
	if message == nil || c.ceiling == 0 {
		return nil
	}
	msg := message.Copy()
	msg.Id = 0
	msg.Compress = true

	if !clampNegativeTTL(msg) {
		return nil
	}

	ttl := c.ceiling
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			h.Ttl = min(h.Ttl, c.ceiling)
			if sig, ok := rr.(*dns.RRSIG); ok {
				// DNSSEC timestamps use serial-number arithmetic.
				remaining := int32(sig.Expiration - uint32(now.Unix()))
				h.Ttl = min(h.Ttl, uint32(max(remaining, 0)))
			}
			ttl = min(ttl, h.Ttl)
		}
	}
	if ttl == 0 {
		return nil
	}
	wire, err := msg.Pack()
	if err != nil || len(wire) > dns.MaxMsgSize {
		return nil
	}
	return &cacheEntry{wire: wire, stored: now, expires: now.Add(time.Duration(ttl) * time.Second)}
}

// clampNegativeTTL returns false for uncachable negative responses which lack
// a relevant SOA. The SOA is aged as an RR, leaving its MINIMUM field intact.
func clampNegativeTTL(msg *dns.Msg) bool {
	if len(msg.Question) != 1 {
		return false
	}
	isNegative, owner := negativeOwner(msg)
	if !isNegative {
		return true
	}
	soa := negativeSOA(msg, owner)
	if soa == nil {
		return false
	}
	soa.Hdr.Ttl = min(soa.Hdr.Ttl, soa.Minttl)
	return true
}

// Only an answer for the queried type at a reachable owner is positive. A
// CNAME-only reply with an SOA can represent a negative for its last target.
func negativeOwner(msg *dns.Msg) (bool, string) {
	q := msg.Question[0]
	owner := dns.CanonicalName(q.Name)
	for range 32 {
		var target string
		for _, rr := range msg.Answer {
			h := rr.Header()
			if h.Class != q.Qclass || dns.CanonicalName(h.Name) != owner {
				continue
			}
			if msg.Rcode == dns.RcodeSuccess && (h.Rrtype == q.Qtype || q.Qtype == dns.TypeANY) {
				return false, owner
			}
			if cname, ok := rr.(*dns.CNAME); ok {
				target = dns.CanonicalName(cname.Target)
			}
		}
		if target == "" || target == owner {
			break
		}
		owner = target
	}
	return true, owner
}

func negativeSOA(msg *dns.Msg, owner string) *dns.SOA {
	var best *dns.SOA
	for _, rr := range msg.Ns {
		soa, ok := rr.(*dns.SOA)
		if !ok || soa.Hdr.Class != msg.Question[0].Qclass {
			continue
		}
		if dns.IsSubDomain(dns.CanonicalName(soa.Hdr.Name), owner) &&
			(best == nil || dns.CountLabel(soa.Hdr.Name) > dns.CountLabel(best.Hdr.Name)) {
			best = soa
		}
	}
	return best
}

func (c *responseCache) put(key cacheKey, entry *cacheEntry) {
	if previous := c.entries[key]; previous != nil {
		c.remove(previous)
	}
	for len(c.entries) >= c.limit || c.bytes+len(entry.wire) > cacheByteLimit {
		c.remove(c.order.Back())
	}
	entry.key = key
	c.entries[key] = c.order.PushFront(entry)
	c.bytes += len(entry.wire)
}

func (c *responseCache) remove(item *list.Element) {
	entry := item.Value.(*cacheEntry)
	delete(c.entries, entry.key)
	c.bytes -= len(entry.wire)
	c.order.Remove(item)
}
