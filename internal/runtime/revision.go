package runtime

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"time"

	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/inventory"
)

func appliedStateChanged(old, next config.State, now time.Time) bool {
	if !sameDesired(old.Desired, next.Desired) || len(old.Devices) != len(next.Devices) {
		return true
	}
	for id, device := range next.Devices {
		previous, ok := old.Devices[id]
		if !ok || !sameDevicePublicationAndBindings(previous, device, now) {
			return true
		}
	}
	for id, source := range next.Desired.Subscriptions {
		if !source.Enabled {
			continue
		}
		a, aExists := old.Artifacts[id]
		b, bExists := next.Artifacts[id]
		if aExists != bExists || a.Digest != b.Digest || a.Source != b.Source {
			return true
		}
	}
	return false
}

func sameDesired(a, b config.Desired) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	// Use the persistent representation to equate omitted empty fields. An
	// explicit empty service or subscription selection is still distinct.
	left, leftErr := json.Marshal(a)
	right, rightErr := json.Marshal(b)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}

func sameDevicePublicationAndBindings(a, b config.Device, now time.Time) bool {
	// Reported names and hostnames also participate in local DNS suppressions.
	if a.Canonical != b.Canonical || a.Reported != b.Reported || a.Hostname != b.Hostname ||
		a.Connected != b.Connected || a.Legacy != b.Legacy || a.LegacyOwner != b.LegacyOwner ||
		a.Controller != b.Controller || a.Site != b.Site || a.MAC != b.MAC || a.SourceID != b.SourceID {
		return false
	}
	fresh := func(d config.Device, addr config.Address) bool {
		at := inventory.SourceBindingTime(d, addr)
		return !at.IsZero() && !at.After(now) && !at.Add(inventory.SourceMaxAge).Before(now)
	}
	return slices.EqualFunc(a.Addresses, b.Addresses, func(left, right config.Address) bool {
		return left.IP == right.IP && left.Active == right.Active && left.Publish == right.Publish &&
			left.Superseded == right.Superseded && left.Reassigned == right.Reassigned &&
			left.Conflicted == right.Conflicted && fresh(a, left) == fresh(b, right)
	})
}
