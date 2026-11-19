package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/pridkett/marco/internal/config"
)

// Label converts a reported label or hostname into a publishable DNS label.
func Label(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if _, err := net.ParseMAC(value); err == nil {
		return ""
	}
	if len(value) == 12 {
		if _, err := hex.DecodeString(value); err == nil {
			return ""
		}
	}
	value, _, _ = strings.Cut(value, ".")
	var label strings.Builder
	for _, c := range value {
		if label.Len() == 63 {
			break
		}
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			label.WriteByte(byte(c))
		case label.Len() > 0 && label.String()[label.Len()-1] != '-':
			label.WriteByte('-')
		}
	}
	out := strings.TrimRight(label.String(), "-")
	if _, err := net.ParseMAC(out); err == nil {
		return ""
	}
	return out
}

// Prepare materializes manual devices and reserves canonical names in the
// candidate before publication. Sources that disappear retain their reservation.
func Prepare(state *config.State) error {
	if state.Devices == nil {
		state.Devices = make(map[string]config.Device)
	}
	for id, device := range state.Devices {
		if id == "" || device.ID != id {
			return fmt.Errorf("inventory entry %q has a mismatched device ID", id)
		}
		if device.Controller == "" && !device.Legacy {
			if _, exists := state.Desired.Devices[id]; !exists {
				delete(state.Devices, id)
			}
		}
	}
	for id := range state.Desired.Devices {
		if strings.TrimSpace(id) != id || id == "" {
			return fmt.Errorf("invalid device setting ID %q", id)
		}
		if _, exists := state.Devices[id]; !exists {
			state.Devices[id] = config.Device{ID: id}
		}
	}
	links, err := LinkTargets(state)
	if err != nil {
		return err
	}
	pinned := make(map[netip.Addr]string)
	for id, settings := range state.Desired.Devices {
		for _, addr := range settings.Pinned {
			if !validAddress(addr) {
				return fmt.Errorf("device %q has invalid pinned address %s", id, addr)
			}
			addr = addr.Unmap()
			if owner := pinned[addr]; owner != "" && owner != links[id] {
				return fmt.Errorf("pinned address %s is assigned to multiple devices", addr)
			}
			pinned[addr] = links[id]
		}
	}

	ids := slices.Sorted(maps.Keys(state.Devices))
	reserved := make(map[string]string)
	// Existing names take precedence during automatic renames and new allocations.
	for _, id := range ids {
		device := state.Devices[id]
		if device.Canonical == "" {
			continue
		}
		if Label(device.Canonical) != device.Canonical {
			return fmt.Errorf("device %q has invalid canonical label %q", id, device.Canonical)
		}
		if other := reserved[device.Canonical]; other != "" {
			return fmt.Errorf("devices %q and %q share canonical label %q", other, id, device.Canonical)
		}
		reserved[device.Canonical] = id
	}

	for _, id := range ids {
		settings := state.Desired.Devices[id]
		if settings.Name == "" {
			continue
		}
		label := Label(settings.Name)
		if label == "" {
			return fmt.Errorf("device %q has invalid operator name %q", id, settings.Name)
		}
		if other := reserved[label]; other != "" && other != id {
			return fmt.Errorf("device %q name %q is already reserved by %q", id, label, other)
		}
		device := state.Devices[id]
		delete(reserved, device.Canonical)
		device.Canonical = label
		state.Devices[id] = device
		reserved[label] = id
	}
	for _, id := range ids {
		device := state.Devices[id]
		if state.Desired.Devices[id].Name != "" || (device.Canonical != "" && !state.Desired.AutoRename) {
			continue
		}
		label := Label(device.Reported)
		if label == "" {
			label = Label(device.Hostname)
		}
		if label == "" {
			continue
		}
		label = allocate(label, id, reserved)
		delete(reserved, device.Canonical)
		reserved[label] = id
		device.Canonical = label
		state.Devices[id] = device
	}
	return nil
}

func allocate(label, id string, reserved map[string]string) string {
	if other := reserved[label]; other == "" || other == id {
		return label
	}
	hash := sha256.Sum256([]byte(id))
	for n := 4; n <= 24; n += 2 {
		suffix := hex.EncodeToString(hash[:n])
		prefix := strings.TrimRight(label[:min(len(label), 62-len(suffix))], "-")
		candidate := prefix + "-" + suffix
		if other := reserved[candidate]; other == "" || other == id {
			return candidate
		}
	}
	for n := 2; ; n++ {
		suffix := fmt.Sprintf("-%x-%d", hash[:4], n)
		candidate := strings.TrimRight(label[:min(len(label), 63-len(suffix))], "-") + suffix
		if other := reserved[candidate]; other == "" || other == id {
			return candidate
		}
	}
}

// LinkTargets maps every interface ID to its explicitly configured primary
// device. A settings entry owns the IDs listed in its Links field.
func LinkTargets(state *config.State) (map[string]string, error) {
	parents := make(map[string]string)
	for id, settings := range state.Desired.Devices {
		for _, child := range settings.Links {
			if _, exists := state.Devices[child]; !exists || id == child {
				return nil, fmt.Errorf("device %q has invalid interface link %q", id, child)
			}
			if existing := parents[child]; existing != "" {
				return nil, fmt.Errorf("interface %q is linked more than once", child)
			}
			parents[child] = id
		}
	}
	out := make(map[string]string, len(state.Devices))
	for id := range state.Devices {
		path := make(map[string]bool)
		cur := id
		for parents[cur] != "" && out[cur] == "" {
			if path[cur] {
				return nil, fmt.Errorf("interface links contain a cycle at %q", cur)
			}
			path[cur] = true
			cur = parents[cur]
		}
		if out[cur] != "" {
			cur = out[cur]
		}
		out[id] = cur
		for member := range path {
			out[member] = cur
		}
	}
	return out, nil
}
