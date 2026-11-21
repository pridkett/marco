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
	Title, Path, CSRF          string
	DisplayName                string
	Revision, EditRevision     uint64
	Nav                        []navItem
	Desired                    config.Desired
	Ready                      bool
	Feedback                   feedback
	Status, LocalIssues        any
	Stats                      querylog.Stats
	Range                      string
	Counts                     querylog.Counts
	Dashboard                  dashboard
	PollStatus                 []siteStatus
	Devices                    []deviceRow
	DeviceSearch, DeviceFilter string
	DeviceSort, DeviceOrder    string
	DeviceColumns              []deviceColumn
	DevicePollURL              string
	DeviceHistoryURL           string
	DeviceID, DeviceGroup      string
	DeviceServiceFilterURL     string
	NewDevice                  bool
	Subscriptions              []sourceRow
	Services                   servicePage
	ServiceFilter              serviceFilterPage
	AliasStatus                map[string]string
	EditText, PoolText         string
	EditBase, ImportBase       string
	History                    []queryDay
	HistoryClient, HistoryName string
	HistoryType                string
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
	HistoryURL string
}

type deviceAddress struct {
	IP     netip.Addr
	Status string
}

type sourceRow struct {
	ID       string
	Spec     config.Subscription
	State    string
	Info     config.Artifact
	EditBase string
}

func (s *server) page(w http.ResponseWriter, r *http.Request, session auth.Session, path string, status int, f feedback) {
	var state config.State
	if s.hooks.Snapshot != nil {
		state = s.hooks.Snapshot()
	}
	p := page{
		Title: "Dashboard", Path: path, DisplayName: session.DisplayName, CSRF: session.CSRF, Revision: state.Revision,
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
	var editOperation, editTarget string
	switch path {
	case "/":
		s.dashboard(r.Context(), &p, r.URL.Query().Get("range"), state, now)
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
		p.stats(s.history)
		if p.Stats.Enabled {
			for i := range p.Devices {
				row := &p.Devices[i]
				row.HistoryURL = s.deviceHistoryURL(row.Device, row.Assigned)
			}
		}
		p.sortDevices(r.URL.Query().Get("sort"), r.URL.Query().Get("order"))
	case "/devices/edit":
		p.Title = "Edit device"
		p.DeviceID = r.URL.Query().Get("id")
		p.NewDevice = r.URL.Query().Get("new") == "1" || r.PostForm.Get("create") == "1"
		if f.DeviceID != "" {
			p.DeviceID = f.DeviceID
		}
		device, observed := state.Devices[p.DeviceID]
		settings, configured := state.Desired.Devices[p.DeviceID]
		if p.NewDevice {
			p.Title = "Add manual device"
		} else if observed || configured {
			editOperation, editTarget = "edit-device", p.DeviceID
			p.DeviceServiceFilterURL = serviceFilterURL("device:" + p.DeviceID)
			p.stats(s.history)
			if p.Stats.Enabled {
				p.DeviceHistoryURL = s.deviceHistoryURL(device, settings)
			}
		} else if status == http.StatusOK {
			p.Feedback.Error = "The requested device no longer exists."
			status = http.StatusNotFound
		}
		p.DeviceGroup, settings.Group = settings.Group, ""
		if f.DeviceGroup != nil {
			p.DeviceGroup = *f.DeviceGroup
		}
		p.EditText = pretty(settings)
	case "/local-dns":
		editOperation = "edit-local-dns"
		p.EditText = pretty(localConfig(state.Desired))
		p.AliasStatus = s.aliasStatus(state.Desired.Records)
		if s.hooks.LocalIssues != nil {
			p.LocalIssues = s.hooks.LocalIssues()
		}
	case "/policies":
		editOperation = "edit-policies"
		p.EditText = pretty(policyConfig(state.Desired))
	case "/services":
		status = s.servicePage(&p, r, state.Desired)
	case "/services/filter":
		p.Title = "Filter services"
		status = s.serviceFilterPage(&p, r, state, status)
		editOperation, editTarget = "edit-service-filter", p.ServiceFilter.Target
	case "/blocklists":
		editOperation = "edit-blocklists"
		p.Subscriptions = sourceRows(state)
		p.EditText = prettyObject(state.Desired.Subscriptions)
		if s.hooks.Status != nil {
			p.Status = s.hooks.Status()
		}
	case "/query-log":
		p.stats(s.history)
		status = s.queryHistory(&p, r, state, now)
	case "/settings":
		editOperation = "edit-upstreams"
		p.ImportBase = scopedEditBase(state, "import-settings", "")
		if f.Operation == "import-settings" {
			p.ImportBase = f.EditBase
		}
		p.PoolText = prettyObject(state.Desired.Pools)
		if f.Endpoints != "" {
			p.PoolText = f.Endpoints
		}
		if s.hooks.Status != nil {
			p.Status = s.hooks.Status()
		}
	}
	if editOperation != "" {
		p.EditBase = scopedEditBase(state, editOperation, editTarget)
		if f.Operation == editOperation && !f.ServiceReview {
			p.EditBase = f.EditBase
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
		row := sourceRow{ID: id, Spec: spec, Info: info, EditBase: scopedEditBase(state, "toggle-list", id)}
		switch {
		case !spec.Enabled:
			row.State = "Disabled"
		case !loaded:
			row.State = "Waiting for valid list"
		case info.Source != spec:
			row.State = "Retaining last good list"
		default:
			row.State = "Active"
		}
		rows = append(rows, row)
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
		if strings.Contains(address.IP.String(), search) {
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
			status = ""
			row.Published = "Publishable"
		}
		row.Addresses = append(row.Addresses, deviceAddress{address.IP, status})
		if !effective.IsValid() && (address.Active || address.Publish) && !address.Conflicted && !address.Reassigned {
			effective = address.IP
		}
	}
	for _, ip := range row.Assigned.Pinned {
		if !seen[ip.Unmap()] {
			row.Addresses = append(row.Addresses, deviceAddress{ip, "Pinned"})
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

type outcomeBadge struct {
	Kind, Label string
}

type queryDay struct {
	Date string
	Rows []queryRow
}

type queryRow struct {
	querylog.Entry
	Hostname string
}

func (r queryRow) LatencyLabel() string {
	if r.Latency < time.Millisecond {
		return fmt.Sprintf("%d µs", r.Latency.Microseconds())
	}
	return fmt.Sprintf("%.2f ms", float64(r.Latency)/float64(time.Millisecond))
}

func queryBadge(entry querylog.Entry) outcomeBadge {
	if entry.Origin == "policy" {
		return outcomeBadge{"blocked", "Blocked"}
	}
	if entry.RCode != dns.RcodeSuccess && entry.RCode != dns.RcodeNameError {
		return outcomeBadge{"error", "Error"}
	}
	if entry.UpstreamBlocked() {
		return outcomeBadge{"upstream-blocked", "Upstream block"}
	}
	if entry.AllowedByRule() {
		return outcomeBadge{"allowed", "Allowed"}
	}
	switch entry.Origin {
	case "local":
		return outcomeBadge{"local", "Local DNS"}
	case "cache":
		return outcomeBadge{"cache", "Cache hit"}
	case "upstream":
		return outcomeBadge{"upstream", "Upstream"}
	default:
		return outcomeBadge{"other", "Other"}
	}
}

func (s *server) queryHistory(p *page, r *http.Request, state config.State, now time.Time) int {
	if s.history == nil || !p.Stats.Enabled {
		return http.StatusOK
	}
	q := r.URL.Query()
	p.HistoryClient, p.HistoryName, p.HistoryOutcome = q.Get("client"), q.Get("question"), q.Get("outcome")
	p.HistoryType = strings.TrimSpace(q.Get("type"))
	p.HistoryAfter, p.HistoryUntil = q.Get("after"), q.Get("until")
	after, startErr := formTime(p.HistoryAfter)
	until, endErr := formTime(p.HistoryUntil)
	if startErr != nil || endErr != nil || (!after.IsZero() && !until.IsZero() && !after.Before(until)) {
		p.Feedback.Error = "Enter a valid UTC time range."
		return http.StatusBadRequest
	}
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	filter := querylog.Filter{
		Client: p.HistoryClient, Question: p.HistoryName, Outcome: p.HistoryOutcome, After: after, Until: until, BeforeID: before,
	}
	if p.HistoryType != "" {
		qtype, ok := historyQuestionType(p.HistoryType)
		if !ok {
			p.Feedback.Error = "Enter a DNS type such as A, AAAA, HTTPS, or TYPE65400."
			return http.StatusBadRequest
		}
		filter.Type = &qtype
	}
	history, err := s.history.Search(r.Context(), filter)
	if err != nil {
		p.Feedback.Error = "Query history is temporarily unavailable."
		return http.StatusServiceUnavailable
	}
	hostnames := make(map[string]string)
	for _, entry := range history.Entries {
		date := entry.Time.UTC().Format(time.DateOnly)
		if len(p.History) == 0 || p.History[len(p.History)-1].Date != date {
			p.History = append(p.History, queryDay{Date: date})
		}
		hostname, ok := hostnames[entry.Client]
		if !ok {
			hostname = s.queryClientName(entry.Client, state, now)
			hostnames[entry.Client] = hostname
		}
		day := &p.History[len(p.History)-1]
		day.Rows = append(day.Rows, queryRow{entry, hostname})
	}
	params := url.Values{"client": {p.HistoryClient}, "question": {p.HistoryName},
		"outcome": {p.HistoryOutcome}, "after": {p.HistoryAfter}, "until": {p.HistoryUntil}}
	if p.HistoryType != "" {
		params.Set("type", p.HistoryType)
	}
	if before > 0 {
		p.HistoryFirst = "/query-log?" + params.Encode()
	}
	if history.Next > 0 {
		params.Set("before", strconv.FormatInt(history.Next, 10))
		p.HistoryMore = "/query-log?" + params.Encode()
	}
	return http.StatusOK
}

func historyQuestionType(value string) (uint16, bool) {
	for qtype, label := range dns.TypeToString {
		if strings.EqualFold(value, label) {
			return qtype, true
		}
	}
	if digits, ok := strings.CutPrefix(strings.ToUpper(value), "TYPE"); ok {
		qtype, err := strconv.ParseUint(digits, 10, 16)
		return uint16(qtype), err == nil
	}
	return 0, false
}

func (s *server) queryClientName(client string, state config.State, now time.Time) string {
	ip, err := netip.ParseAddr(client)
	if err != nil {
		return ""
	}
	ip = ip.Unmap().WithZone("")
	if s.hooks.Lookup != nil {
		reverse, err := dns.ReverseAddr(ip.String())
		if err == nil {
			for _, record := range s.hooks.Lookup(reverse, dns.TypePTR).Answer {
				if ptr, ok := record.(*dns.PTR); ok && ptr.Ptr != "." {
					return strings.TrimSuffix(ptr.Ptr, ".")
				}
			}
		}
	}
	if s.hooks.Select == nil {
		return ""
	}
	selected := s.hooks.Select(ip, now)
	if selected.Confidence != "observed" && selected.Precedence != "static" {
		return ""
	}
	device := state.Devices[selected.Device]
	// A subnet policy can name a device even when a different host sent the query.
	if selected.Precedence == "subnet" && !slices.ContainsFunc(device.Addresses, func(address config.Address) bool {
		return address.IP.Unmap() == ip && address.Active && !address.Conflicted && !address.Reassigned && !address.Superseded
	}) {
		return ""
	}
	for _, name := range []string{device.Canonical, device.Hostname, state.Desired.Devices[selected.Device].Name} {
		if name != "" {
			return strings.TrimSuffix(name, ".")
		}
	}
	return ""
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
