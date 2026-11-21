package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/pridkett/marco/internal/config"
)

var errEditConflict = errors.New("the edited settings changed")

// The scope value comes from the same snapshot as the form. The operation and
// target bind the comparison to the fields the submission can replace.
func scopeDigest(operation, target string, value any) string {
	data, err := json.Marshal(struct {
		Operation, Target string
		Value             any
	}{operation, target, value})
	if err != nil {
		panic(err) // Scope values are projections of already serialized settings.
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func scopedEditBase(state config.State, operation, target string) string {
	d := state.Desired
	var value any
	switch operation {
	case "edit-device":
		settings, configured := d.Devices[target]
		_, observed := state.Devices[target]
		if !configured && !observed {
			return ""
		}
		value = settings
	case "edit-local-dns":
		value = localConfig(d)
	case "edit-policies":
		value = policyConfig(d)
	case "edit-blocklists":
		value = d.Subscriptions
	case "toggle-list":
		spec, ok := d.Subscriptions[target]
		if !ok {
			return ""
		}
		value = spec
	case "edit-upstreams":
		value = struct {
			Pools      map[string][]config.Endpoint
			Forwarding map[string]string
		}{d.Pools, d.Forwarding}
	case "import-settings":
		value = d
	case "edit-service-filter":
		if scope, ok := serviceScope(state, target); ok {
			return scope.editBase(target)
		}
		return ""
	default:
		return ""
	}
	return scopeDigest(operation, target, value)
}

func editBaseMatches(state config.State, operation, target, submitted, mode string) bool {
	if operation == "edit-service-filter" {
		scope, ok := serviceScope(state, target)
		if !ok {
			return false
		}
		latest := scope.editBase(target)
		// A custom list edited as a custom list does not depend on its parent's list.
		if scope.Policy.Services != nil && mode == "custom" {
			before, _, valid := strings.Cut(submitted, ".")
			after, _, _ := strings.Cut(latest, ".")
			return valid && before == after
		}
		return submitted == latest
	}
	return submitted == scopedEditBase(state, operation, target)
}
