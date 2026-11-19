package admin

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/auth"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/querylog"
)

type page struct {
	Title, Path, Account, CSRF string
	Revision, EditRevision     uint64
	Nav                        []navItem
	Desired                    config.Desired
	Ready                      bool
	Feedback                   feedback
	Status, LocalIssues        any
	Stats                      querylog.Stats
	Range                      string
	Counts                     querylog.Counts
	PollStatus                 []siteStatus
	Devices                    []deviceRow
	DeviceSearch, DeviceFilter string
	DeviceID                   string
	NewDevice                  bool
	Subscriptions              []sourceRow
	AliasStatus                map[string]string
	EditText, PoolText         string
	History                    querylog.Page
	HistoryClient, HistoryName string
	HistoryOutcome             string
	HistoryAfter, HistoryUntil string
	HistoryMore                string
	HistoryFirst               string
}

type siteStatus struct {
	Title   string
	Updated time.Time
}

type deviceRow struct {
	config.Device
	Assigned   config.DeviceSettings
	Mode       string
	PolicyFrom string
	Published  string
	Presence   string
	Addresses  []deviceAddress
}

type deviceAddress struct {
	IP     string
	Status string
}

type sourceRow struct {
	ID    string
	Spec  config.Subscription
	State string
	Info  config.Artifact
}

func (s *server) page(w http.ResponseWriter, r *http.Request, session auth.Session, path string, status int, f feedback) {
	var state config.State
	if s.hooks.Snapshot != nil {
		state = s.hooks.Snapshot()
	}
	p := page{
		Title: "Overview", Path: path, Account: session.Account, CSRF: session.CSRF, Revision: state.Revision,
		EditRevision: state.Revision, Nav: navigation, Desired: state.Desired, Feedback: f,
		Ready: s.hooks.Ready != nil && s.hooks.Ready(),
	}
	for _, nav := range navigation {
		if nav.URL == path {
			p.Title = nav.Label
			break
		}
	}
	if f.StaleBase != nil {
		p.EditRevision = *f.StaleBase
	}
	if value, err := strconv.ParseUint(r.URL.Query().Get("applied"), 10, 64); err == nil && value > 0 && value <= state.Revision && f.Message == "" && f.Error == "" {
		p.Feedback.Message = fmt.Sprintf("Applied revision %d.", value)
	}
	now := time.Now()
	switch path {
	case "/":
		p.stats(s.history)
		p.Range = r.URL.Query().Get("range")
		if _, ok := p.Stats.Recent[p.Range]; !ok {
			p.Range = "15 minutes"
		}
		p.Counts = p.Stats.Recent[p.Range]
		p.PollStatus = siteRows(state.SitePolls)
		p.Subscriptions = sourceRows(state)
		if s.hooks.Status != nil {
			p.Status = s.hooks.Status()
		}
	case "/devices":
		if s.hooks.LocalIssues != nil {
			p.LocalIssues = s.hooks.LocalIssues()
		}
		p.DeviceSearch, p.DeviceFilter = r.URL.Query().Get("search"), r.URL.Query().Get("presence")
		p.Devices = s.deviceRows(state, p.DeviceSearch, p.DeviceFilter, now)
	case "/devices/edit":
		p.Title = "Edit device"
		p.DeviceID = r.URL.Query().Get("id")
		p.NewDevice = r.URL.Query().Get("new") == "1" || r.PostForm.Get("create") == "1"
		if f.DeviceID != "" {
			p.DeviceID = f.DeviceID
		}
		if p.NewDevice {
			p.Title = "Add manual device"
		} else if _, observed := state.Devices[p.DeviceID]; !observed {
			if _, configured := state.Desired.Devices[p.DeviceID]; !configured {
				if status == http.StatusOK {
					p.Feedback.Error = "The requested device no longer exists."
					status = http.StatusNotFound
				}
			}
		}
		p.EditText = pretty(state.Desired.Devices[p.DeviceID])
	case "/local-dns":
		p.EditText = pretty(localConfig(state.Desired))
		p.AliasStatus = s.aliasStatus(state.Desired.Records)
		if s.hooks.LocalIssues != nil {
			p.LocalIssues = s.hooks.LocalIssues()
		}
	case "/policies":
		p.EditText = pretty(policyConfig(state.Desired))
	case "/blocklists":
		p.Subscriptions = sourceRows(state)
		p.EditText = prettyObject(state.Desired.Subscriptions)
		if s.hooks.Status != nil {
			p.Status = s.hooks.Status()
		}
	case "/query-log":
		p.stats(s.history)
		p.queryHistory(r, s.history)
	case "/settings":
		p.PoolText = prettyObject(state.Desired.Pools)
		if f.Endpoints != "" {
			p.PoolText = f.Endpoints
		}
		if s.hooks.Status != nil {
			p.Status = s.hooks.Status()
		}
	}
	if f.Draft != "" {
		p.EditText = f.Draft
	}
	render(w, status, "main", p)
}

func (p *page) stats(l *querylog.Log) {
	if l != nil {
		p.Stats = l.Stats()
	}
}

func siteRows(polls map[string]time.Time) []siteStatus {
	rows := make([]siteStatus, 0, len(polls))
	for _, site := range slices.Sorted(maps.Keys(polls)) {
		rows = append(rows, siteStatus{site, polls[site]})
	}
	return rows
}

func sourceRows(state config.State) []sourceRow {
	rows := make([]sourceRow, 0, len(state.Desired.Subscriptions))
	for _, id := range slices.Sorted(maps.Keys(state.Desired.Subscriptions)) {
		spec := state.Desired.Subscriptions[id]
		info, loaded := state.Artifacts[id]
		switch {
		case !spec.Enabled:
			rows = append(rows, sourceRow{id, spec, "Disabled", info})
		case !loaded:
			rows = append(rows, sourceRow{id, spec, "Waiting for valid list", info})
		case info.Source != spec:
			rows = append(rows, sourceRow{id, spec, "Retaining last good list", info})
		default:
			rows = append(rows, sourceRow{id, spec, "Active", info})
		}
	}
	return rows
}

func (s *server) deviceRows(state config.State, search, filter string, now time.Time) []deviceRow {
	devices := maps.Clone(state.Devices)
	if devices == nil {
		devices = make(map[string]config.Device)
	}
	for id := range state.Desired.Devices {
		if _, installed := devices[id]; !installed {
			devices[id] = config.Device{ID: id, Canonical: state.Desired.Devices[id].Name}
		}
	}
	rows := make([]deviceRow, 0, len(devices))
	search = strings.ToLower(visible(search))
	for id, device := range devices {
		cfg := state.Desired.Devices[id]
		row := deviceRow{Device: device, Assigned: cfg, Presence: presence(device), Published: "No address"}
		if row.ID == "" {
			row.ID = id
		}
		s.deviceAddresses(&row, now)
		switch {
		case cfg.Unpublish:
			row.Published = "Disabled"
		case s.hooks.Published != nil && s.hooks.Published(row.ID):
			row.Published = "Published"
		case s.hooks.Published != nil:
			row.Published = "Unpublished"
		}
		if filter != "" && row.Presence != filter {
			continue
		}
		if search != "" && !row.matches(search) {
			continue
		}
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b deviceRow) int {
		if cmp := strings.Compare(a.Canonical, b.Canonical); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.ID, b.ID)
	})
	return rows
}

func presence(d config.Device) string {
	switch {
	case d.Legacy:
		return "Legacy observation"
	case d.Controller == "":
		return "Manual"
	case d.Connected:
		return "Connected at last poll"
	default:
		return "Absent at last poll"
	}
}

func (r deviceRow) matches(search string) bool {
	for _, value := range []string{r.ID, r.Canonical, r.Reported, r.MAC, r.Hostname, r.Network, r.Assigned.Group} {
		if strings.Contains(strings.ToLower(value), search) {
			return true
		}
	}
	for _, address := range r.Addresses {
		if strings.Contains(address.IP, search) {
			return true
		}
	}
	return false
}

func (s *server) deviceAddresses(row *deviceRow, now time.Time) {
	var effective netip.Addr
	seen := make(map[netip.Addr]bool)
	for _, address := range row.Device.Addresses {
		status := "Observed"
		seen[address.IP.Unmap()] = true
		switch {
		case address.Conflicted:
			status = "Ownership conflict"
		case address.Reassigned:
			status = "Reassigned"
		case address.Superseded:
			status = "Historical"
		case address.Publish:
			status = "Publishable"
			row.Published = "Publishable"
		}
		row.Addresses = append(row.Addresses, deviceAddress{address.IP.String(), status})
		if !effective.IsValid() && (address.Active || address.Publish) && !address.Conflicted && !address.Reassigned {
			effective = address.IP
		}
	}
	for _, ip := range row.Assigned.Pinned {
		if !seen[ip.Unmap()] {
			row.Addresses = append(row.Addresses, deviceAddress{ip.String(), "Pinned"})
		}
		if !effective.IsValid() {
			effective = ip
		}
	}
	if effective.IsValid() {
		s.devicePolicy(row, effective, now)
	}
}

func (s *server) devicePolicy(row *deviceRow, address netip.Addr, now time.Time) {
	switch {
	case s.hooks.Select != nil:
		selected := s.hooks.Select(address, now)
		row.Mode, row.PolicyFrom = string(selected.Policy.Mode), selected.Precedence
	case s.hooks.Preview != nil:
		answer, err := s.probe(address.String(), "example.invalid.", "A")
		if err == nil {
			row.Mode, row.PolicyFrom = string(answer.Selection.Policy.Mode), answer.Selection.Precedence
		}
	}
}

func (s *server) aliasStatus(records []config.Record) map[string]string {
	status := make(map[string]string)
	for _, record := range records {
		if !strings.EqualFold(record.Type, "CNAME") || s.hooks.Lookup == nil {
			continue
		}
		name, err := config.Name(record.Name)
		if err != nil {
			continue
		}
		status[record.Name] = "Unresolved"
		for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypePTR} {
			res := s.hooks.Lookup(name, kind)
			if res.PublicTarget != "" {
				status[record.Name] = "Public target"
				break
			}
			for _, rr := range res.Answer {
				if rr.Header().Rrtype != dns.TypeCNAME {
					status[record.Name] = "Local chain"
					break
				}
			}
		}
	}
	return status
}

func (p *page) queryHistory(r *http.Request, l *querylog.Log) {
	if l == nil || !p.Stats.Enabled {
		return
	}
	q := r.URL.Query()
	p.HistoryClient, p.HistoryName, p.HistoryOutcome = q.Get("client"), q.Get("question"), q.Get("outcome")
	p.HistoryAfter, p.HistoryUntil = q.Get("after"), q.Get("until")
	after, startErr := formTime(p.HistoryAfter)
	until, endErr := formTime(p.HistoryUntil)
	if startErr != nil || endErr != nil || (!after.IsZero() && !until.IsZero() && !after.Before(until)) {
		p.Feedback.Error = "Enter a valid UTC time range."
		return
	}
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	history, err := l.Search(r.Context(), querylog.Filter{
		Client: p.HistoryClient, Question: p.HistoryName, Outcome: p.HistoryOutcome, After: after, Until: until, BeforeID: before,
	})
	if err != nil {
		p.Feedback.Error = "Query history is temporarily unavailable."
		return
	}
	p.History = history
	params := url.Values{"client": {p.HistoryClient}, "question": {p.HistoryName},
		"outcome": {p.HistoryOutcome}, "after": {p.HistoryAfter}, "until": {p.HistoryUntil}}
	if before > 0 {
		p.HistoryFirst = "/query-log?" + params.Encode()
	}
	if history.Next > 0 {
		params.Set("before", strconv.FormatInt(history.Next, 10))
		p.HistoryMore = "/query-log?" + params.Encode()
	}
}

func formTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	return time.Parse("2006-01-02T15:04", value)
}

func pretty(value any) string {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

func prettyObject(value any) string {
	text := pretty(value)
	if text == "null" {
		return "{}"
	}
	return text
}

func editQuery(id string, revision uint64) url.Values {
	q := url.Values{"applied": {strconv.FormatUint(revision, 10)}}
	if id != "" {
		q.Set("id", id)
	}
	return q
}

func (s *server) export(w http.ResponseWriter, _ *http.Request, _ auth.Session) {
	if s.hooks.Snapshot == nil {
		http.Error(w, "Portable configuration is currently unavailable.", http.StatusServiceUnavailable)
		return
	}
	state := s.hooks.Snapshot()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="marco-settings.json"`)
	w.Header().Set("X-Marco-Revision", strconv.FormatUint(state.Revision, 10))
	fmt.Fprintln(w, pretty(state.Desired))
}
