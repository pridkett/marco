package admin

import (
	"cmp"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/pridkett/marco/internal/config"
)

type serviceFilterEdit struct {
	Target, Mode string
	Services     []string
}

type serviceFilterPage struct {
	Target, Name, Group, Device string
	Mode                        config.Mode
	Custom                      bool
	Selected, Inherited         int
	Categories                  []string
	Groups, Devices             []serviceFilterOption
	Cards                       []serviceFilterCard
}

type serviceFilterOption struct {
	Value, Label string
}

type serviceFilterCard struct {
	serviceCard
	Selected, Inherited bool
}

func serviceFilterURL(target string) string {
	return "/services/filter?" + url.Values{"target": {target}}.Encode()
}

func serviceFilterPolicy(state config.State, target string) (config.Policy, bool) {
	kind, id, _ := strings.Cut(target, ":")
	switch kind {
	case "group":
		p, exists := state.Desired.Groups[id]
		return p, exists
	case "device":
		d, configured := state.Desired.Devices[id]
		_, observed := state.Devices[id]
		return d.Policy, configured || observed
	}
	return config.Policy{}, false
}

func deviceFilterName(state config.State, id string) string {
	d := state.Devices[id]
	return cmp.Or(d.Canonical, state.Desired.Devices[id].Name, d.Reported, d.Hostname, id)
}

func (s *server) serviceFilterPage(p *page, r *http.Request, state config.State, status int) int {
	edit := p.Feedback.ServiceEdit
	f := &p.ServiceFilter
	f.Target = r.URL.Query().Get("target")
	if edit != nil {
		f.Target = edit.Target
	}
	for _, group := range slices.Sorted(maps.Keys(state.Desired.Groups)) {
		f.Groups = append(f.Groups, serviceFilterOption{"group:" + group, group})
	}
	devices := make(map[string]struct{})
	for id := range state.Devices {
		devices[id] = struct{}{}
	}
	for id := range state.Desired.Devices {
		devices[id] = struct{}{}
	}
	for id := range devices {
		name := deviceFilterName(state, id)
		if name != id {
			name += " · " + id
		}
		f.Devices = append(f.Devices, serviceFilterOption{"device:" + id, name})
	}
	slices.SortFunc(f.Devices, func(a, b serviceFilterOption) int {
		return cmp.Or(compareDeviceText(a.Label, b.Label), strings.Compare(a.Value, b.Value))
	})
	if f.Target == "" {
		return status
	}
	current, ok := serviceFilterPolicy(state, f.Target)
	if !ok {
		if status == http.StatusOK {
			p.Feedback.Error = "The selected group or device no longer exists."
			return http.StatusNotFound
		}
		return status
	}
	parent := state.Desired.Default
	kind, id, _ := strings.Cut(f.Target, ":")
	f.Name = id
	if kind == "device" {
		f.Device = id
		f.Name = deviceFilterName(state, id)
		f.Group = state.Desired.Devices[id].Group
		group := state.Desired.Groups[f.Group]
		parent.Mode = cmp.Or(group.Mode, parent.Mode)
		if group.Services != nil {
			parent.Services = group.Services
		}
	}
	f.Mode = cmp.Or(current.Mode, parent.Mode, config.Filtered)
	f.Custom = current.Services != nil
	inherited := serviceIDs(parent.Services)
	selected := inherited
	if f.Custom {
		selected = *current.Services
	}
	if edit != nil && (edit.Mode == "custom" || edit.Mode == "inherit") {
		f.Custom, selected = edit.Mode == "custom", edit.Services
		if !f.Custom {
			selected = inherited
		}
	}
	categories := make(map[string]bool)
	for id, card := range s.serviceCards(state.Desired) {
		item := serviceFilterCard{card, slices.Contains(selected, id), slices.Contains(inherited, id)}
		f.Cards = append(f.Cards, item)
		categories[card.Category] = true
		if item.Selected {
			f.Selected++
		}
		if item.Inherited {
			f.Inherited++
		}
	}
	f.Categories = slices.Sorted(maps.Keys(categories))
	slices.SortFunc(f.Cards, func(a, b serviceFilterCard) int { return compareServices(a.serviceCard, b.serviceCard) })
	return status
}

func serviceIDs(ids *[]string) []string {
	if ids != nil {
		return *ids
	}
	return nil
}

func (s *server) changeServiceFilter(edit serviceFilterEdit) func(*config.State) error {
	return func(state *config.State) error {
		if edit.Mode != "inherit" && edit.Mode != "custom" {
			return settingsInputError("Choose whether to inherit or customize service blocks.")
		}
		current, ok := serviceFilterPolicy(*state, edit.Target)
		if !ok {
			return settingsInputError("Choose an existing group or device.")
		}
		kind, id, _ := strings.Cut(edit.Target, ":")
		var selection *[]string
		if edit.Mode == "custom" {
			known := s.serviceCards(state.Desired)
			pending := make(map[string]bool)
			for _, service := range edit.Services {
				if _, exists := known[service]; !exists {
					return settingsInputError("A selected service is unavailable. Reload the editor and try again.")
				}
				pending[service] = true
			}
			// Keep existing match order for DNS query log attribution.
			ids := make([]string, 0, len(pending))
			for _, order := range [][]string{serviceIDs(current.Services), edit.Services} {
				for _, service := range order {
					if pending[service] {
						ids = append(ids, service)
						delete(pending, service)
					}
				}
			}
			selection = &ids
		}
		if kind == "group" {
			current.Services = selection
			state.Desired.Groups[id] = current
			return nil
		}
		if current.Services == nil && selection == nil {
			return nil
		}
		device := state.Desired.Devices[id]
		device.Policy.Services = selection
		if state.Desired.Devices == nil {
			state.Desired.Devices = make(map[string]config.DeviceSettings)
		}
		state.Desired.Devices[id] = device
		return nil
	}
}
