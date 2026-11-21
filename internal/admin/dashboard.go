package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pridkett/marco/internal/auth"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
	"github.com/pridkett/marco/internal/querylog"
)

type activityRange struct {
	Key      string
	Label    string
	Window   time.Duration
	Interval time.Duration
}

var activityRanges = []activityRange{
	{"15m", "15 minutes", 15 * time.Minute, time.Minute},
	{"1h", "1 hour", time.Hour, 5 * time.Minute},
	{"24h", "24 hours", 24 * time.Hour, time.Hour},
}

type pauseOption struct {
	Label    string
	Value    string
	Duration time.Duration
}

var pauseOptions = []pauseOption{
	{"1 minute", "1m", time.Minute},
	{"5 minutes", "5m", 5 * time.Minute},
	{"15 minutes", "15m", 15 * time.Minute},
	{"30 minutes", "30m", 30 * time.Minute},
	{"1 hour", "1h", time.Hour},
	{"4 hours", "4h", 4 * time.Hour},
	{"12 hours", "12h", 12 * time.Hour},
	{"24 hours", "24h", 24 * time.Hour},
	{"Indefinite", "indefinite", 0},
}

type blockingStatus struct {
	contract.BlockingPause
	RemainingSeconds int64 `json:"remainingSeconds"`
}

type dashboard struct {
	Ranges       []activityRange
	PauseOptions []pauseOption
	Control      bool
	Blocking     blockingStatus
	Activity     []querylog.ActivityPoint
	Start, End   string
	HistoryURL   string
	Rankings     []rankPanel
	RankError    bool
}

type rankPanel struct {
	Title, Label, Empty string
	Rows                []rankRow
	Max                 uint64
}

type rankRow struct {
	Label, Detail, URL string
	Count              uint64
}

func (s *server) dashboard(ctx context.Context, p *page, selected string, state config.State, now time.Time) {
	d := &p.Dashboard
	d.Control = s.hooks.Blocking != nil && s.hooks.SetBlocking != nil
	d.Blocking = s.readBlocking(now)
	d.PauseOptions, d.Ranges = pauseOptions, activityRanges
	window := activityRanges[len(activityRanges)-1]
	for _, option := range activityRanges {
		if selected == option.Label {
			window = option
		}
	}
	p.Range = window.Label
	if s.history == nil {
		return
	}
	p.stats(s.history)
	d.Activity, p.Counts = s.history.Activity(now, window.Window, window.Interval)
	start := d.Activity[0].Time
	timeLabel := "15:04"
	if start.Day() != now.UTC().Day() {
		timeLabel = "Jan 2, 15:04"
	}
	d.Start, d.End = start.Format(timeLabel), now.UTC().Format(timeLabel)
	if !p.Stats.Enabled {
		return
	}
	historyLink := func(key, value, outcome string) string {
		params := url.Values{"after": {start.Format("2006-01-02T15:04")}}
		if key != "" {
			params.Set(key, value)
		}
		if outcome != "" {
			params.Set("outcome", outcome)
		}
		return "/query-log?" + params.Encode()
	}
	d.HistoryURL = historyLink("", "", "")
	ctx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer cancel()
	top, err := s.history.TopQueries(ctx, start, now)
	if err != nil {
		d.RankError = true
		return
	}
	for _, group := range []struct {
		title, label, key, outcome, empty string
		entries                           []querylog.RankedEntry
	}{
		{"Top clients", "Client", "client", "", "No client queries in this range.", top.Clients},
		{"Top queried domains", "Domain", "question", "", "No queried domains in this range.", top.Domains},
		{"Top blocked domains", "Domain", "question", "blocked", "No blocked domains in this range.", top.Blocked},
		{"Top upstream-blocked domains", "Domain", "question", "upstream blocked",
			"No upstream-blocked domains in this range.", top.UpstreamBlocked},
	} {
		panel := rankPanel{Title: group.title, Label: group.label, Empty: group.empty}
		for _, entry := range group.entries {
			label, detail := strings.TrimSuffix(entry.Value, "."), ""
			if group.key == "client" {
				if name := s.queryClientName(entry.Value, state, now); name != "" {
					label, detail = name, entry.Value
				}
			}
			if label == "" {
				label = entry.Value
			}
			panel.Rows = append(panel.Rows, rankRow{label, detail, historyLink(group.key, entry.Value, group.outcome), entry.Count})
			panel.Max = max(panel.Max, entry.Count)
		}
		d.Rankings = append(d.Rankings, panel)
	}
}

func (s *server) readBlocking(now time.Time) blockingStatus {
	if s.hooks.Blocking == nil {
		return blockingStatus{}
	}
	pause := s.hooks.Blocking(now)
	status := blockingStatus{BlockingPause: pause}
	if pause.Paused && !pause.Until.IsZero() {
		status.RemainingSeconds = int64((pause.Until.Sub(now) + time.Second - 1) / time.Second)
	}
	return status
}

func (s *server) blockingStatus(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	if s.hooks.Blocking == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.readBlocking(time.Now()))
}

func (s *server) updateBlocking(w http.ResponseWriter, r *http.Request, session auth.Session) {
	if s.hooks.Blocking == nil || s.hooks.SetBlocking == nil {
		http.NotFound(w, r)
		return
	}
	reject := func(status int, message string) {
		s.page(w, r, session, "/", status, feedback{Error: message})
	}
	if err := parseForm(w, r, 8<<10); err != nil {
		reject(http.StatusBadRequest, err.Error())
		return
	}
	if err := s.auth.CheckCSRF(r, session.CSRF, r.PostForm.Get("csrf")); err != nil {
		s.audit(r, session.Account, "update-blocking", outcome(err), s.revision())
		reject(http.StatusForbidden, "Reload the page and try again.")
		return
	}
	duration := r.PostForm.Get("duration")
	var pause contract.BlockingPause
	if duration != "resume" {
		for _, option := range pauseOptions {
			if option.Value == duration {
				pause.Paused = true
				if option.Duration > 0 {
					pause.Until = time.Now().UTC().Add(option.Duration)
				}
				break
			}
		}
		if !pause.Paused {
			reject(http.StatusBadRequest, "Choose a supported pause duration.")
			return
		}
	}
	if err := s.hooks.SetBlocking(r.Context(), session.Account, pause); err != nil {
		s.audit(r, session.Account, "update-blocking", outcome(err), s.revision())
		reject(http.StatusServiceUnavailable, "Blocking status could not be saved. Try again.")
		return
	}
	http.Redirect(w, r, "/?"+url.Values{"range": {r.URL.Query().Get("range")}}.Encode(), http.StatusSeeOther)
}

func formatCount(n uint64) string {
	digits := strconv.FormatUint(n, 10)
	var grouped strings.Builder
	for i, digit := range digits {
		if i > 0 && (len(digits)-i)%3 == 0 {
			grouped.WriteByte(',')
		}
		grouped.WriteRune(digit)
	}
	return grouped.String()
}
