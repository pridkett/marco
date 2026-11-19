package localdns

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/config"
)

func rrHeader(name string, rtype uint16, ttl uint32) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: rtype, Class: dns.ClassINET, Ttl: ttl}
}

func addressRR(name string, ip netip.Addr, ttl uint32) dns.RR {
	if ip.Is4() {
		a := ip.As4()
		return &dns.A{Hdr: rrHeader(name, dns.TypeA, ttl), A: net.IP(a[:])}
	}
	a := ip.As16()
	return &dns.AAAA{Hdr: rrHeader(name, dns.TypeAAAA, ttl), AAAA: net.IP(a[:])}
}

func (v *View) record(spec config.Record) (dns.RR, error) {
	name, err := config.Name(spec.Name)
	if err != nil {
		return nil, err
	}
	ttl := spec.TTL
	if ttl == 0 {
		ttl = v.staticTTL
	}
	typ := strings.ToUpper(strings.TrimSpace(spec.Type))
	if spec.Public && typ != "CNAME" {
		return nil, fmt.Errorf("public target mode is available for CNAME records")
	}
	switch typ {
	case "A", "AAAA":
		ip, err := netip.ParseAddr(strings.TrimSpace(spec.Value))
		if err != nil || ip.Zone() != "" || ip.Is4In6() || (typ == "A") != ip.Is4() {
			return nil, fmt.Errorf("%s has invalid %s address %q", name, typ, spec.Value)
		}
		return addressRR(name, ip, ttl), nil
	case "CNAME", "PTR":
		target, err := config.Name(spec.Value)
		if err != nil {
			return nil, err
		}
		if typ == "PTR" {
			return &dns.PTR{Hdr: rrHeader(name, dns.TypePTR, ttl), Ptr: target}, nil
		}
		if target == name {
			return nil, fmt.Errorf("CNAME %s points to itself", name)
		}
		return &dns.CNAME{Hdr: rrHeader(name, dns.TypeCNAME, ttl), Target: target}, nil
	default:
		return nil, fmt.Errorf("unsupported local record type %q", spec.Type)
	}
}

func (v *View) add(rr dns.RR, public, multiplePTRs bool) error {
	h := rr.Header()
	e := v.owners[h.Name]
	if e == nil {
		e = &owner{sets: make(map[uint16][]dns.RR)}
		v.owners[h.Name] = e
	}
	set := e.sets[h.Rrtype]
	for _, old := range set {
		if dns.IsDuplicate(rr, old) {
			if h.Ttl != old.Header().Ttl || public != e.public {
				return fmt.Errorf("conflicting record settings at %s", h.Name)
			}
			return nil
		}
	}
	switch {
	case h.Rrtype == dns.TypeCNAME && len(e.sets) != 0,
		h.Rrtype != dns.TypeCNAME && len(e.sets[dns.TypeCNAME]) != 0:
		return fmt.Errorf("conflicting CNAME owner %s", h.Name)
	case h.Rrtype == dns.TypePTR && len(set) > 0 && !multiplePTRs:
		return fmt.Errorf("multiple PTR records at %s require multiplePTRs", h.Name)
	case len(set) > 0 && h.Ttl != set[0].Header().Ttl:
		return fmt.Errorf("conflicting TTLs in record set at %s", h.Name)
	}
	e.sets[h.Rrtype] = append(set, rr)
	e.public = public
	return nil
}
