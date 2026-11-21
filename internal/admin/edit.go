package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/auth"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
	"github.com/pridkett/marco/internal/store"
)

type localSettings struct {
	Zones        []config.Zone        `json:"zones"`
	Reverse      []netip.Prefix       `json:"reverse"`
	Records      []config.Record      `json:"records"`
	Suppressions []config.Suppression `json:"suppressions"`
	DynamicTTL   uint32               `json:"dynamicTTL"`
	StaticTTL    uint32               `json:"staticTTL"`
	MultiplePTRs bool                 `json:"multiplePTRs"`
	AutoRename   bool                 `json:"autoRename"`
}

func localConfig(d config.Desired) localSettings {
	return localSettings{d.Zones, d.Reverse, d.Records, d.Suppressions, d.DynamicTTL, d.StaticTTL, d.MultiplePTRs, d.AutoRename}
}

type policySettings struct {
	Default     config.Policy             `json:"default"`
	Groups      map[string]config.Policy  `json:"groups"`
	Assignments []config.Assignment       `json:"assignments"`
	Services    map[string]config.Service `json:"services"`
}

func policyConfig(d config.Desired) policySettings {
	return policySettings{d.Default, d.Groups, d.Assignments, d.Services}
}

func (cfg policySettings) apply(d *config.Desired) {
	d.Default, d.Groups, d.Assignments, d.Services = cfg.Default, cfg.Groups, cfg.Assignments, cfg.Services
}

type feedback struct {
	Error, Message string
	Draft          string
	DeviceID       string
	DeviceGroup    *string
	Answer         *probeAnswer
	Upstream       any
	Endpoints      string
	SettingsImport string
	StaleBase      *uint64
	ServiceEdit    *serviceFilterEdit
	Operation      string
	EditBase       string
	Conflict       bool
	ServiceReview  bool
}

type settingsInputError string

func (err settingsInputError) Error() string { return string(err) }

func (s *server) edit(w http.ResponseWriter, r *http.Request, session auth.Session, path, operation string) {
	if err := parseForm(w, r, 4<<20); err != nil {
		s.audit(r, session.Account, operation, "invalid-form", s.revision())
		s.page(w, r, session, path, http.StatusBadRequest, feedback{Error: err.Error()})
		return
	}
	if err := s.auth.CheckCSRF(r, session.CSRF, r.PostForm.Get("csrf")); err != nil {
		s.audit(r, session.Account, operation, "csrf-rejected", s.revision())
		s.page(w, r, session, path, http.StatusForbidden, feedback{Error: "Reload the page and try again."})
		return
	}
	form := r.PostForm
	draft := feedback{Draft: form.Get("settings"), DeviceID: visible(form.Get("id")),
		Operation: operation, EditBase: form.Get("edit-base")}
	if operation == "edit-device" && form.Get("group-picker") == "1" {
		group := form.Get("group")
		draft.DeviceGroup = &group
	}
	if operation == "edit-upstreams" {
		draft.Endpoints, draft.Draft = draft.Draft, ""
	}
	if operation == "import-settings" {
		draft.SettingsImport, draft.Draft = draft.Draft, ""
	}
	if operation == "edit-service-filter" {
		draft.ServiceEdit = &serviceFilterEdit{form.Get("target"), form.Get("mode"), form["service"]}
	}
	target, mode := draft.DeviceID, ""
	if draft.ServiceEdit != nil {
		target, mode = draft.ServiceEdit.Target, draft.ServiceEdit.Mode
	} else if operation == "toggle-list" {
		target = form.Get("id")
	}
	additive := operation == "add-default-groups" || operation == "add-default-lists" ||
		operation == "create-group" || (operation == "edit-device" && form.Get("create") == "1")
	base, err := strconv.ParseUint(form.Get("revision"), 10, 64)
	status := http.StatusBadRequest
	current := s.revision()
	var audit *store.ChangeAudit
	if err != nil || base == 0 {
		err = errors.New("A valid base revision is required.")
	} else if s.hooks.Update == nil {
		status = http.StatusServiceUnavailable
		err = errors.New("Settings are currently read-only.")
	} else {
		var change func(*config.State) error
		if draft.ServiceEdit != nil {
			change = s.changeServiceFilter(*draft.ServiceEdit)
		} else {
			change, err = changeFor(operation, form.Get)
		}
		if err == nil {
			ctx, changeAudit := store.WithChangeAudit(r.Context(), session.Account, operation)
			audit = changeAudit
			switch {
			case additive:
				current, err = s.hooks.Update(ctx, 0, change)
			case draft.EditBase != "":
				current, err = s.hooks.Update(ctx, 0, func(candidate *config.State) error {
					if !editBaseMatches(*candidate, operation, target, draft.EditBase, mode) {
						return errEditConflict
					}
					return change(candidate)
				})
			default:
				// Forms opened before the upgrade can still use their original revision.
				current, err = s.hooks.Update(ctx, base, change)
			}
			switch {
			case errors.Is(err, store.ErrBusy):
				status, err = http.StatusServiceUnavailable, errors.New("Marco is busy. Try the edit again.")
			case errors.Is(err, errEditConflict):
				status = http.StatusConflict
				draft.ServiceReview = draft.ServiceEdit != nil
				if draft.ServiceReview {
					err = errors.New("The service policy changed while you were editing. Review the current blocks and your selection below.")
				} else {
					err = errors.New("These settings changed while you were editing. Copy your edits, then reload the current settings.")
				}
			case errors.Is(err, store.ErrStale):
				status, err = http.StatusConflict, conflict(base, current)
			case err != nil && (draft.ServiceEdit != nil || operation == "create-group"):
				var invalid settingsInputError
				if !errors.As(err, &invalid) {
					slog.Warn("could not update admin settings", "operation", operation, "revision", current, "error", err)
					status, err = http.StatusInternalServerError, errors.New("Marco could not save the settings. Check the server log.")
				}
			}
		}
	}
	if err != nil {
		result := "invalid"
		if base > 0 {
			draft.StaleBase = &base
		}
		if status == http.StatusConflict {
			result = "stale"
			draft.Conflict = true
		}
		s.audit(r, session.Account, operation, result, current)
		draft.Error = err.Error()
		s.page(w, r, session, path, status, draft)
		return
	}
	if !audit.Saved() && !s.audit(r, session.Account, operation, "success", current) {
		draft = feedback{Error: "The change applied, but its audit record could not be saved.", ServiceEdit: draft.ServiceEdit}
		s.page(w, r, session, path, http.StatusOK, draft)
		return
	}
	w.Header().Set("X-Marco-Revision", strconv.FormatUint(current, 10))
	if draft.ServiceEdit != nil {
		query := editQuery("", current)
		query.Set("target", draft.ServiceEdit.Target)
		http.Redirect(w, r, path+"?"+query.Encode(), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, redirectPath(path, draft.DeviceID, current), http.StatusSeeOther)
}

func conflict(base, current uint64) error {
	return fmt.Errorf("Revision %d is stale. Revision %d is active. Copy any edits, then reload before trying again.", base, current)
}

func redirectPath(path, id string, rev uint64) string {
	return path + "?" + editQuery(id, rev).Encode()
}

func changeFor(operation string, get func(string) string) (func(*config.State) error, error) {
	text := get("settings")
	switch operation {
	case "edit-device":
		id := visible(get("id"))
		if id == "" || len(id) > 256 || strings.ContainsAny(id, "\r\n\t ") {
			return nil, errors.New("Device ID is required and may contain up to 256 characters without spaces.")
		}
		var settings config.DeviceSettings
		if err := decode(text, &settings); err != nil {
			return nil, err
		}
		if get("group-picker") == "1" {
			settings.Group = get("group")
		}
		return func(s *config.State) error {
			if settings.Group != "" {
				if _, exists := s.Desired.Groups[settings.Group]; !exists {
					return fmt.Errorf("Unknown device group %q.", settings.Group)
				}
			}
			if get("create") == "1" {
				_, known := s.Devices[id]
				_, configured := s.Desired.Devices[id]
				if known || configured {
					return errors.New("A device with that ID already exists.")
				}
			}
			if s.Desired.Devices == nil {
				s.Desired.Devices = make(map[string]config.DeviceSettings)
			}
			s.Desired.Devices[id] = settings
			return nil
		}, nil
	case "edit-local-dns":
		var cfg localSettings
		if err := decode(text, &cfg); err != nil {
			return nil, err
		}
		return func(s *config.State) error {
			d := &s.Desired
			d.Zones, d.Reverse, d.Records, d.Suppressions = cfg.Zones, cfg.Reverse, cfg.Records, cfg.Suppressions
			d.DynamicTTL, d.StaticTTL, d.MultiplePTRs, d.AutoRename = cfg.DynamicTTL, cfg.StaticTTL, cfg.MultiplePTRs, cfg.AutoRename
			return nil
		}, nil
	case "edit-policies":
		var cfg policySettings
		if err := decode(text, &cfg); err != nil {
			return nil, err
		}
		return func(s *config.State) error {
			cfg.apply(&s.Desired)
			return nil
		}, nil
	case "add-default-groups":
		return func(s *config.State) error {
			if s.Desired.Groups == nil {
				s.Desired.Groups = config.DefaultGroups()
			} else {
				for name, group := range config.DefaultGroups() {
					if _, exists := s.Desired.Groups[name]; !exists {
						s.Desired.Groups[name] = group
					}
				}
			}
			return nil
		}, nil
	case "create-group":
		name := strings.TrimSpace(get("group-name"))
		if name == "" || len([]rune(name)) > 64 || strings.ContainsFunc(name, unicode.IsControl) {
			return nil, errors.New("Enter a group name of up to 64 characters on one line.")
		}
		return func(s *config.State) error {
			if _, exists := s.Desired.Groups[name]; exists {
				return settingsInputError("A group with that name already exists.")
			}
			if s.Desired.Groups == nil {
				s.Desired.Groups = make(map[string]config.Policy)
			}
			s.Desired.Groups[name] = config.Policy{}
			return nil
		}, nil
	case "add-default-lists":
		return func(s *config.State) error {
			if s.Desired.Subscriptions == nil {
				s.Desired.Subscriptions = config.DefaultSubscriptions()
			} else {
				for id, preset := range config.DefaultSubscriptions() {
					if _, exists := s.Desired.Subscriptions[id]; !exists && !hasSubscription(s.Desired.Subscriptions, preset) {
						s.Desired.Subscriptions[id] = preset
					}
				}
			}
			return nil
		}, nil
	case "edit-blocklists":
		var lists map[string]config.Subscription
		if err := decode(text, &lists); err != nil {
			return nil, err
		}
		return func(s *config.State) error { s.Desired.Subscriptions = lists; return nil }, nil
	case "toggle-list":
		id := get("id")
		enabled, err := strconv.ParseBool(get("enabled"))
		if err != nil {
			return nil, errors.New("List status must be enabled or disabled.")
		}
		return func(s *config.State) error {
			list, ok := s.Desired.Subscriptions[id]
			if !ok {
				return errors.New("Subscription was removed.")
			}
			list.Enabled = enabled
			s.Desired.Subscriptions[id] = list
			return nil
		}, nil
	case "edit-upstreams":
		var pools map[string][]config.Endpoint
		if err := decode(text, &pools); err != nil {
			return nil, err
		}
		return func(s *config.State) error { s.Desired.Pools = pools; return nil }, nil
	case "import-settings":
		var cfg config.Desired
		if err := decode(text, &cfg); err != nil {
			return nil, err
		}
		if cfg.Version != config.Version {
			return nil, fmt.Errorf("Settings file must use version %d.", config.Version)
		}
		return func(s *config.State) error { s.Desired = cfg; return nil }, nil
	default:
		return nil, errors.New("Unknown settings operation.")
	}
}

func hasSubscription(lists map[string]config.Subscription, preset config.Subscription) bool {
	for _, list := range lists {
		if list.URL == preset.URL && list.Allowlist == preset.Allowlist {
			return true
		}
	}
	return false
}

func decode(raw string, dst any) error {
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	s := strings.TrimSpace(raw)
	if len(s) == 0 || s[0] != '{' {
		return errors.New("Settings must contain one JSON object.")
	}
	if err := d.Decode(dst); err != nil {
		return fmt.Errorf("Invalid settings JSON: %w", err)
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("Settings must contain only one JSON object.")
	}
	return nil
}

type probeAnswer struct {
	Client, Question, Type string
	Selection              contract.Selection
	Result                 contract.Result
	RCode                  string
	ShowsRCode             bool
}

func (s *server) action(w http.ResponseWriter, r *http.Request, session auth.Session, path, operation string) {
	if err := parseForm(w, r, 8<<10); err != nil {
		s.audit(r, session.Account, operation, "invalid-form", s.revision())
		s.page(w, r, session, path, http.StatusBadRequest, feedback{Error: err.Error()})
		return
	}
	get := r.PostForm.Get
	if err := s.auth.CheckCSRF(r, session.CSRF, get("csrf")); err != nil {
		s.audit(r, session.Account, operation, "csrf-rejected", s.revision())
		s.page(w, r, session, path, http.StatusForbidden, feedback{Error: "Reload the page and try again."})
		return
	}
	var state feedback
	var err error
	switch operation {
	case "poll-controller":
		if s.hooks.Poll == nil {
			err = errors.New("No UniFi controller is configured.")
		} else if err = s.hooks.Poll(); err == nil {
			state.Message = "UniFi poll requested. Controller backoff still applies."
		}
	case "refresh-list":
		if s.hooks.Refresh == nil {
			err = errors.New("List refresh is unavailable.")
		} else if err = s.hooks.Refresh(get("id")); err == nil {
			state.Message = "List refresh requested."
		}
	case "test-policy":
		state.Answer, err = s.probe(get("client"), get("question"), get("type"))
	case "test-upstream":
		if s.hooks.TestUpstream == nil {
			err = errors.New("Upstream testing is unavailable.")
		} else {
			ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
			defer cancel()
			state.Upstream, err = s.hooks.TestUpstream(ctx, get("pool"))
			if err == nil {
				state.Message = "Upstream test completed."
			}
		}
	}
	s.audit(r, session.Account, operation, outcome(err), s.revision())
	code := http.StatusOK
	if err != nil {
		code, state.Error = http.StatusBadRequest, err.Error()
		// Integration details may contain a credential reference, request URL or path.
		if operation == "test-upstream" {
			code, state.Error = http.StatusBadGateway, "Upstream test failed. Check the endpoint health and settings."
		}
	}
	s.page(w, r, session, path, code, state)
}

func (s *server) probe(client, name, kind string) (*probeAnswer, error) {
	if s.hooks.Preview == nil {
		return nil, errors.New("Policy testing is unavailable.")
	}
	ip, err := netip.ParseAddr(visible(client))
	if err != nil || ip.Zone() != "" {
		return nil, errors.New("Enter a valid IPv4 or IPv6 client address.")
	}
	name = visible(name)
	name, err = config.Name(name)
	if err != nil {
		return nil, errors.New("Enter a valid DNS question name.")
	}
	kind = strings.ToUpper(visible(kind))
	qt, ok := dns.StringToType[kind]
	if !ok || qt == dns.TypeAXFR || qt == dns.TypeIXFR {
		return nil, errors.New("Enter a DNS query type such as A, AAAA, PTR, or HTTPS.")
	}
	sel, result := s.hooks.Preview(contract.Input{
		Name: name, Type: qt, Class: dns.ClassINET, Peer: ip.Unmap(), Time: time.Now(), Recursion: true,
	})
	return &probeAnswer{
		Client: ip.String(), Question: name, Type: kind, Selection: sel, Result: result,
		RCode: dns.RcodeToString[result.RCode], ShowsRCode: result.Origin != "upstream",
	}, nil
}
