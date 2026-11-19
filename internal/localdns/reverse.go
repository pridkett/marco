package localdns

import (
	"net/netip"
	"strconv"
	"strings"
)

// reversePrefix decodes reverse address owners, including partial zone owners.
func reversePrefix(name string) (netip.Prefix, bool) {
	const v4 = "in-addr.arpa."
	const v6 = "ip6.arpa."
	switch {
	case within(name, v4):
		labels := reverseParts(name, v4)
		var octets [4]byte
		if len(labels) > len(octets) {
			return netip.Prefix{}, false
		}
		for i, value := range labels {
			octet, err := strconv.ParseUint(value, 10, 8)
			if err != nil || strconv.FormatUint(octet, 10) != value {
				return netip.Prefix{}, false
			}
			octets[len(labels)-1-i] = byte(octet)
		}
		return netip.PrefixFrom(netip.AddrFrom4(octets), len(labels)*8), len(labels) == len(octets)
	case within(name, v6):
		labels := reverseParts(name, v6)
		var octets [16]byte
		if len(labels) > len(octets)*2 {
			return netip.Prefix{}, false
		}
		for i, value := range labels {
			if len(value) != 1 {
				return netip.Prefix{}, false
			}
			hex := strings.IndexByte("0123456789abcdef", value[0])
			if hex < 0 {
				return netip.Prefix{}, false
			}
			j := len(labels) - 1 - i
			octets[j/2] |= byte(hex) << (4 * (1 - j%2))
		}
		return netip.PrefixFrom(netip.AddrFrom16(octets), len(labels)*4), len(labels) == len(octets)*2
	default:
		return netip.Prefix{}, false
	}
}

func reverseParts(name, suffix string) []string {
	if name == suffix {
		return nil
	}
	return strings.Split(strings.TrimSuffix(name, "."+suffix), ".")
}

func (v *View) reverseZone(name string) string {
	if len(v.reverse) == 0 || (!within(name, "in-addr.arpa.") && !within(name, "ip6.arpa.")) {
		return ""
	}
	// A syntactically invalid PTR under an authoritative reverse zone still
	// belongs to that zone. Check enclosing owners if the full name is invalid.
	for candidate := name; candidate != ""; candidate = parentName(candidate) {
		query, _ := reversePrefix(candidate)
		if !query.IsValid() {
			continue
		}
		for _, private := range v.reverse {
			if private.Bits() <= query.Bits() && private.Contains(query.Addr()) {
				stride := 4
				if query.Addr().Is4() {
					stride = 8
				}
				// Round non-aligned CIDRs up to the covered reverse child zones.
				excess := query.Bits()/stride - (private.Bits()+stride-1)/stride
				for range excess {
					candidate = parentName(candidate)
				}
				return candidate
			}
		}
		return ""
	}
	return ""
}
