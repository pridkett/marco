package admin

import (
	"cmp"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
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
		return a.LastSeen.Compare(b.LastSeen)
	}},
	{"poll", "Controller poll", "desc", func(a, b deviceRow) int {
		return a.connectionTime().Compare(b.connectionTime())
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

func (r deviceRow) connectionTime() time.Time {
	switch {
	case r.Controller == "" || r.Legacy:
		return time.Time{}
	case r.Connected && !r.LastPoll.IsZero():
		return r.LastPoll
	case !r.LastConnected.IsZero():
		return r.LastConnected
	default:
		return r.LastSeen
	}
}

func (r deviceRow) PollLabel() string {
	switch r.Presence {
	case "Connected at last poll":
		return "Connected"
	case "Absent at last poll":
		if last := r.connectionTime(); !last.IsZero() {
			return "Last connected " + strings.ToLower(age(last))
		}
		return "Absent"
	default:
		return r.Presence
	}
}

func (r deviceRow) PollTitle() string {
	if last := r.connectionTime(); !last.IsZero() {
		return "Last connected " + dateTime(last)
	}
	return ""
}

const unifiArtworkOrigin = "https://static.ui.com"

func (r deviceRow) IconURL() string {
	if r.UniFiFingerprint == 0 {
		return ""
	}
	return unifiArtworkOrigin + "/fingerprint/0/" + strconv.FormatUint(uint64(r.UniFiFingerprint), 10) + "_101x101.png"
}
