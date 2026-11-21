package runtime

import (
	"net/netip"
	"testing"
	"time"

	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/inventory"
)

func TestAppliedRevisionDistinguishesRenewalAndRecovery(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	snapshot := func(seen time.Time) config.State {
		return config.State{Devices: map[string]config.Device{
			"tablet": {
				ID: "tablet", Connected: true, LastPoll: seen, Addresses: []config.Address{{
					IP: netip.MustParseAddr("192.0.2.12"), Active: true, Publish: true, LastSeen: seen,
				}},
			},
		}}
	}
	renewed := snapshot(now)
	if appliedStateChanged(snapshot(now.Add(-inventory.SourceMaxAge)), renewed, now) {
		t.Error("renewing a binding still eligible at the freshness boundary changed the applied revision")
	}
	if !appliedStateChanged(snapshot(now.Add(-inventory.SourceMaxAge-time.Second)), renewed, now) {
		t.Error("restoring an expired source binding did not change the applied revision")
	}
}
