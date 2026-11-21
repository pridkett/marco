package admin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/pridkett/marco/internal/auth"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/querylog"
	"github.com/pridkett/marco/internal/runtime"
	"github.com/pridkett/marco/internal/store"
)

type dashboardInput struct {
	Range string `json:"range"`
}

type dashboardData struct {
	Range         string                   `json:"range"`
	AsOf          time.Time                `json:"asOf"`
	Revision      uint64                   `json:"revision"`
	Blocking      blockingStatus           `json:"blocking"`
	History       bool                     `json:"historyEnabled"`
	Dropped       uint64                   `json:"droppedHistoryEntries"`
	HistoryError  bool                     `json:"historyWriteError"`
	Counts        querylog.Counts          `json:"counts"`
	AverageMS     *float64                 `json:"averageLatencyMs"`
	CacheHitRate  *float64                 `json:"cacheHitPercent"`
	Activity      []querylog.ActivityPoint `json:"activity"`
	Rankings      *querylog.Rankings       `json:"rankings"`
	RankingsError bool                     `json:"rankingsUnavailable"`
	// RankingsPending means the first rankings for this range are still being
	// calculated. Ask again in a few seconds.
	RankingsPending bool `json:"rankingsPending,omitempty"`
}

func (s *server) managementDashboard(ctx context.Context, _ auth.AccessToken, in dashboardInput) (dashboardData, *managementError) {
	window := activityRanges[len(activityRanges)-1]
	if in.Range != "" {
		i := slices.IndexFunc(activityRanges, func(r activityRange) bool { return r.Key == in.Range })
		if i < 0 {
			return dashboardData{}, badInput("Choose a dashboard range of 15m, 1h, or 24h.")
		}
		window = activityRanges[i]
	}
	now := time.Now().UTC()
	result := dashboardData{Range: window.Key, AsOf: now, Revision: s.revision(), Blocking: s.readBlocking(now)}
	if s.history == nil {
		return result, nil
	}
	stats := s.history.Stats()
	result.History, result.Dropped, result.HistoryError = stats.Enabled, stats.Dropped, stats.Error != ""
	result.Activity, result.Counts = s.history.Activity(now, window.Window, window.Interval)
	if n := result.Counts.Queries; n != 0 {
		mean := float64(result.Counts.Latency) / float64(time.Millisecond) / float64(n)
		result.AverageMS = &mean
	}
	if n := result.Counts.Cache + result.Counts.Misses; n != 0 {
		percent := 100 * float64(result.Counts.Cache) / float64(n)
		result.CacheHitRate = &percent
	}
	if stats.Enabled {
		ctx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
		defer cancel()
		rankings, err := s.history.TopQueries(ctx, result.Activity[0].Time, now)
		if errors.Is(err, querylog.ErrRankingsPending) {
			result.RankingsError, result.RankingsPending = true, true
		} else if err != nil {
			slog.Warn("could not rank management query history", "error", err)
			result.RankingsError = true
		} else {
			rankings.Clients = emptySlice(rankings.Clients)
			rankings.Domains = emptySlice(rankings.Domains)
			rankings.Blocked = emptySlice(rankings.Blocked)
			rankings.UpstreamBlocked = emptySlice(rankings.UpstreamBlocked)
			result.Rankings = &rankings
		}
	}
	return result, nil
}

type historyInput struct {
	Client   string    `json:"client"`
	Question string    `json:"question"`
	Outcome  string    `json:"outcome"`
	Type     string    `json:"type"`
	After    time.Time `json:"after"`
	Until    time.Time `json:"until"`
	Before   int64     `json:"before"`
	Limit    int       `json:"limit"`
}

type historyData struct {
	Enabled bool             `json:"enabled"`
	Entries []querylog.Entry `json:"entries"`
	Next    int64            `json:"next,omitempty"`
}

func (s *server) managementHistory(ctx context.Context, _ auth.AccessToken, in historyInput) (historyData, *managementError) {
	limit, problem := s.managementPageSize(in.Limit)
	if problem != nil {
		return historyData{}, problem
	}
	if in.Before < 0 || len(in.Client) > 4096 || strings.Count(in.Client, ",") >= 64 ||
		len(in.Question) > 253 || len(in.Outcome) > 64 || (!in.After.IsZero() && !in.Until.IsZero() && !in.After.Before(in.Until)) {
		return historyData{}, badInput("Check the history filters, time range, cursor, and limit.")
	}
	filter := querylog.Filter{
		Client: strings.TrimSpace(in.Client), Question: in.Question, Outcome: in.Outcome,
		After: in.After, Until: in.Until, BeforeID: in.Before, Limit: limit,
	}
	if value := strings.TrimSpace(in.Type); value != "" {
		qtype, ok := historyQuestionType(value)
		if !ok {
			return historyData{}, badInput("Enter a DNS type such as A, AAAA, HTTPS, or TYPE65400.")
		}
		filter.Type = &qtype
	}
	if s.history == nil {
		return historyData{Entries: []querylog.Entry{}}, nil
	}
	page, err := s.history.Search(ctx, filter)
	if err != nil {
		slog.Warn("could not read management query history", "error", err)
		return historyData{}, unavailable("Query history is temporarily unavailable.")
	}
	return historyData{s.history.Stats().Enabled, emptySlice(page.Entries), page.Next}, nil
}

type previewInput struct {
	Client   string `json:"client"`
	Question string `json:"question"`
	Type     string `json:"type"`
}

type previewData struct {
	Client     string        `json:"client"`
	Question   string        `json:"question"`
	Type       string        `json:"type"`
	Device     string        `json:"device,omitempty"`
	Group      string        `json:"group,omitempty"`
	Precedence string        `json:"precedence,omitempty"`
	Assignment string        `json:"assignment,omitempty"`
	Confidence string        `json:"confidence,omitempty"`
	Policy     config.Policy `json:"policy"`
	Origin     string        `json:"origin"`
	Reason     string        `json:"reason"`
	Rule       string        `json:"rule,omitempty"`
	RCode      string        `json:"rcode,omitempty"`
}

func (s *server) managementPreview(_ context.Context, _ auth.AccessToken, in previewInput) (previewData, *managementError) {
	if s.hooks.Preview == nil {
		return previewData{}, unavailable("Policy testing is unavailable.")
	}
	question := strings.TrimSpace(in.Question)
	if len(question) > 8192 {
		return previewData{}, badInput("Enter a DNS name or an HTTP or HTTPS URL.")
	}
	if strings.Contains(question, "://") {
		u, err := url.Parse(question)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
			return previewData{}, badInput("Enter a DNS name or an HTTP or HTTPS URL.")
		}
		question = u.Hostname()
	}
	if in.Type == "" {
		in.Type = "A"
	}
	answer, err := s.probe(in.Client, question, in.Type)
	if err != nil {
		return previewData{}, badInput(err.Error())
	}
	sel, result := answer.Selection, answer.Result
	data := previewData{Client: answer.Client, Question: answer.Question, Type: answer.Type, Device: sel.Device,
		Group: sel.Group, Precedence: sel.Precedence, Assignment: sel.Assignment, Confidence: sel.Confidence,
		Policy: sel.Policy, Origin: result.Origin, Reason: result.Reason, Rule: result.Rule}
	if answer.ShowsRCode {
		data.RCode = answer.RCode
	}
	return data, nil
}

type policyData struct {
	Revision uint64         `json:"revision"`
	Settings policySettings `json:"settings"`
	Refs     policyRefs     `json:"references"`
}

type policyRefs struct {
	Pools           []string `json:"pools"`
	Subscriptions   []string `json:"subscriptions"`
	BuiltInServices []string `json:"builtInServices"`
}

type noArguments struct{}

func (s *server) managementPolicies(_ context.Context, _ auth.AccessToken, _ noArguments) (policyData, *managementError) {
	if s.hooks.Snapshot == nil {
		return policyData{}, unavailable("Policy settings are unavailable.")
	}
	state := s.hooks.Snapshot()
	var builtIn []string
	if s.hooks.Catalog != nil {
		builtIn = slices.Sorted(maps.Keys(s.hooks.Catalog.Entries))
	}
	refs := policyRefs{
		Pools:           emptySlice(slices.Sorted(maps.Keys(state.Desired.Pools))),
		Subscriptions:   emptySlice(slices.Sorted(maps.Keys(state.Desired.Subscriptions))),
		BuiltInServices: emptySlice(builtIn),
	}
	return policyData{state.Revision, policyConfig(state.Desired), refs}, nil
}

type policyPatch struct {
	Revision    uint64                     `json:"revision"`
	Default     *config.Policy             `json:"default"`
	Groups      map[string]*config.Policy  `json:"groups"`
	Assignments *[]config.Assignment       `json:"assignments"`
	Services    map[string]*config.Service `json:"services"`
}

type revisionData struct {
	Revision uint64 `json:"revision"`
}

func (s *server) managementPatchPolicy(ctx context.Context, actor auth.AccessToken, patch policyPatch) (revisionData, *managementError) {
	if patch.Revision == 0 {
		return revisionData{}, badInput("Provide the current policy revision.")
	}
	if patch.Default == nil && len(patch.Groups) == 0 && patch.Assignments == nil && len(patch.Services) == 0 {
		return revisionData{}, badInput("Provide at least one policy change.")
	}
	if s.hooks.Update == nil {
		return revisionData{}, unavailable("Policy settings are read-only.")
	}
	const operation = "api-edit-policies"
	ctx, audit := store.WithChangeAudit(ctx, actor.Account, operation)
	rev, err := s.hooks.Update(ctx, patch.Revision, func(state *config.State) error {
		cfg := policyConfig(state.Desired)
		if patch.Default != nil {
			cfg.Default = *patch.Default
		}
		cfg.Groups = applyPolicyEntries(cfg.Groups, patch.Groups)
		if patch.Assignments != nil {
			cfg.Assignments = *patch.Assignments
		}
		cfg.Services = applyPolicyEntries(cfg.Services, patch.Services)
		cfg.apply(&state.Desired)
		return nil
	})
	result := outcome(err)
	if errors.Is(err, store.ErrStale) {
		result = "stale"
	}
	if !audit.Saved() {
		auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		if auditErr := s.auth.Audit(auditCtx, actor.Account, operation, result, rev); auditErr != nil {
			slog.Warn("could not write management audit record", "operation", operation, "revision", rev)
		}
	}
	var invalid *runtime.CompileError
	switch {
	case err == nil:
		return revisionData{rev}, nil
	case errors.Is(err, store.ErrStale):
		return revisionData{}, &managementError{http.StatusConflict, fmt.Sprintf("Revision %d is active. Reload the policies before retrying.", rev)}
	case errors.As(err, &invalid):
		slog.Warn("management policy validation failed", "revision", rev, "error", err)
		return revisionData{}, &managementError{http.StatusUnprocessableEntity, "The policy could not be compiled. Check the policy references and server log."}
	default:
		slog.Warn("management policy update failed", "revision", rev, "error", err)
		return revisionData{}, unavailable("The policy update could not be saved. Try again.")
	}
}

func applyPolicyEntries[T any](current map[string]T, changes map[string]*T) map[string]T {
	for name, entry := range changes {
		if entry == nil {
			delete(current, name)
			continue
		}
		if current == nil {
			current = make(map[string]T)
		}
		current[name] = *entry
	}
	return current
}

type devicesInput struct {
	ID         string `json:"id"`
	Search     string `json:"search"`
	Controller string `json:"controller"`
	Site       string `json:"site"`
	Presence   string `json:"presence"`
	After      string `json:"after"`
	Limit      int    `json:"limit"`
}

type clientData struct {
	config.Device
	Group       string        `json:"group,omitempty"`
	Policy      config.Policy `json:"policy"`
	Presence    string        `json:"presence"`
	Published   bool          `json:"published"`
	Unpublished bool          `json:"publicationDisabled"`
	Pinned      []netip.Addr  `json:"pinned,omitempty"`
}

type devicesData struct {
	Revision  uint64               `json:"revision"`
	Devices   []clientData         `json:"devices"`
	SitePolls map[string]time.Time `json:"sitePolls,omitempty"`
	Next      string               `json:"next,omitempty"`
}

func (s *server) managementDevices(_ context.Context, _ auth.AccessToken, in devicesInput) (devicesData, *managementError) {
	if s.hooks.Snapshot == nil {
		return devicesData{}, unavailable("Client inventory is unavailable.")
	}
	limit, problem := s.managementPageSize(in.Limit)
	if problem != nil {
		return devicesData{}, problem
	}
	if len(in.Search) > 256 || len(in.ID) > 256 || len(in.After) > 256 ||
		len(in.Controller) > 256 || len(in.Site) > 256 ||
		!slices.Contains([]string{"", "connected", "absent", "manual", "legacy"}, in.Presence) {
		return devicesData{}, badInput("Check the client filters, cursor, and limit.")
	}
	state := s.hooks.Snapshot()
	result := devicesData{Revision: state.Revision, SitePolls: state.SitePolls, Devices: []clientData{}}
	keys := make(map[string]struct{}, len(state.Devices)+len(state.Desired.Devices))
	for id := range state.Devices {
		keys[id] = struct{}{}
	}
	for id := range state.Desired.Devices {
		keys[id] = struct{}{}
	}
	search := strings.ToLower(strings.TrimSpace(in.Search))
	for _, id := range slices.Sorted(maps.Keys(keys)) {
		if id <= in.After || in.ID != "" && id != in.ID {
			continue
		}
		d, cfg := state.Devices[id], state.Desired.Devices[id]
		d.ID = id
		if d.Canonical == "" {
			d.Canonical = cfg.Name
		}
		status := "absent"
		switch {
		case d.Legacy:
			status = "legacy"
		case d.Controller == "":
			status = "manual"
		case d.Connected:
			status = "connected"
		}
		if in.Presence != "" && status != in.Presence || in.Site != "" && d.Site != in.Site ||
			in.Controller != "" && d.Controller != in.Controller {
			continue
		}
		row := deviceRow{Device: d, Assigned: cfg}
		if search != "" && !row.matches(search) &&
			!slices.ContainsFunc(d.Addresses, func(a config.Address) bool { return strings.Contains(a.IP.String(), search) }) &&
			!slices.ContainsFunc(cfg.Pinned, func(ip netip.Addr) bool { return strings.Contains(ip.String(), search) }) {
			continue
		}
		if len(result.Devices) == limit {
			result.Next = result.Devices[len(result.Devices)-1].ID
			break
		}
		result.Devices = append(result.Devices, clientData{
			Device: d, Group: cfg.Group, Policy: cfg.Policy, Presence: status, Pinned: cfg.Pinned,
			Unpublished: cfg.Unpublish, Published: s.hooks.Published != nil && s.hooks.Published(id),
		})
	}
	return result, nil
}

func emptySlice[T any](value []T) []T {
	if value == nil {
		return []T{}
	}
	return value
}
