package admin

import (
	"cmp"
	"maps"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pridkett/marco/internal/config"
)

type deviceColumn struct {
	Label, URL, Direction, Arrow string
}

type deviceSortColumn struct {
	key, label, firstOrder string
	compare                func(deviceRow, deviceRow) int
}

var deviceSortColumns = []deviceSortColumn{
	{"device", "Device", "asc", func(a, b deviceRow) int {
		return compareDeviceText(a.DisplayName(), b.DisplayName())
	}},
	{"addresses", "Addresses", "asc", func(a, b deviceRow) int {
		return a.firstAddress().Compare(b.firstAddress())
	}},
	{"network", "Network", "asc", func(a, b deviceRow) int {
		return compareDeviceText(a.Network, b.Network)
	}},
	{"policy", "Policy", "asc", func(a, b deviceRow) int {
		return cmp.Or(compareDeviceText(a.Mode, b.Mode), compareDeviceText(a.PolicyFrom, b.PolicyFrom))
	}},
	{"seen", "Last seen", "desc", func(a, b deviceRow) int {
		return a.SeenAt().Compare(b.SeenAt())
	}},
	{"publication", "Publication", "asc", func(a, b deviceRow) int {
		return compareDeviceText(a.Published, b.Published)
	}},
}

func (p *page) sortDevices(key, order string) {
	index := slices.IndexFunc(deviceSortColumns, func(column deviceSortColumn) bool {
		return column.key == key
	})
	if index < 0 {
		index, order = 0, ""
	}
	selected := deviceSortColumns[index]
	if order != "asc" && order != "desc" {
		order = selected.firstOrder
	}
	p.DeviceSort, p.DeviceOrder = selected.key, order
	slices.SortFunc(p.Devices, func(a, b deviceRow) int {
		result := selected.compare(a, b)
		if order == "desc" {
			result = -result
		}
		if result != 0 {
			return result
		}
		return cmp.Or(deviceSortColumns[0].compare(a, b), strings.Compare(a.ID, b.ID))
	})

	params := make(url.Values)
	if p.DeviceSearch != "" {
		params.Set("search", p.DeviceSearch)
	}
	if p.DeviceFilter != "" {
		params.Set("presence", p.DeviceFilter)
	}
	params.Set("sort", selected.key)
	params.Set("order", order)
	p.DevicePollURL = "/devices/poll?" + params.Encode()
	for _, column := range deviceSortColumns {
		header := deviceColumn{Label: column.label, Arrow: "↕"}
		next := column.firstOrder
		if column.key == selected.key {
			if order == "asc" {
				header.Direction, header.Arrow, next = "ascending", "↑", "desc"
			} else {
				header.Direction, header.Arrow, next = "descending", "↓", "asc"
			}
		}
		params.Set("sort", column.key)
		params.Set("order", next)
		header.URL = "/devices?" + params.Encode()
		p.DeviceColumns = append(p.DeviceColumns, header)
	}
}

func compareDeviceText(a, b string) int {
	return strings.Compare(strings.ToLower(a), strings.ToLower(b))
}

func (r deviceRow) DisplayName() string {
	if r.Canonical != "" {
		return r.Canonical
	}
	return r.ID
}

func (r deviceRow) firstAddress() netip.Addr {
	if len(r.Addresses) != 0 {
		return r.Addresses[0].IP.Unmap()
	}
	return netip.Addr{}
}

func (r deviceRow) SeenAt() time.Time {
	if !r.LastSeen.IsZero() {
		return r.LastSeen
	}
	return r.LastConnected
}

func (s *server) deviceHistoryURL(device config.Device, settings config.DeviceSettings) string {
	addresses := make(map[netip.Addr]struct{})
	for _, ip := range settings.Pinned {
		if ip.IsValid() {
			addresses[ip.Unmap().WithZone("")] = struct{}{}
		}
	}
	for _, address := range device.Addresses {
		if !address.IP.IsValid() {
			continue
		}
		ip := address.IP.Unmap().WithZone("")
		if address.Conflicted || address.Reassigned || address.Superseded {
			delete(addresses, ip)
		} else {
			addresses[ip] = struct{}{}
		}
	}
	if len(addresses) == 0 {
		return ""
	}
	clients := make([]string, 0, len(addresses))
	for _, ip := range slices.SortedFunc(maps.Keys(addresses), netip.Addr.Compare) {
		clients = append(clients, s.history.ClientID(ip))
	}
	return "/query-log?" + url.Values{"client": {strings.Join(clients, ",")}}.Encode()
}

const unifiArtworkOrigin = "https://static.ui.com"

func (r deviceRow) IconURL() string {
	if r.UniFiFingerprint == 0 {
		return ""
	}
	return unifiArtworkOrigin + "/fingerprint/0/" + strconv.FormatUint(uint64(r.UniFiFingerprint), 10) + "_101x101.png"
}
