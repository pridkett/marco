package filter

import (
	"context"
	"fmt"
	"hash/fnv"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/pridkett/marco/internal/config"
)

type Publisher interface {
	Snapshot() config.State
	ReadArtifact(string) (config.Artifact, bool)
	Update(context.Context, uint64, func(*config.State) error) (uint64, error)
}

type SourceStatus struct {
	ID       string        `json:"id"`
	State    string        `json:"state"`
	Digest   string        `json:"digest,omitempty"`
	Rules    int           `json:"rules"`
	LastGood time.Time     `json:"lastGood,omitempty"`
	Attempt  time.Time     `json:"attempt,omitempty"`
	Duration time.Duration `json:"duration,omitempty"`
	Failures uint64        `json:"failures,omitempty"`
	Error    string        `json:"error,omitempty"`
}

type attempt struct {
	start    time.Time
	next     time.Time
	duration time.Duration
	error    string
	failures uint64
	streak   int
	source   config.Subscription
}

type Worker struct {
	db       Publisher
	fetcher  *Fetcher
	interval time.Duration
	started  time.Time
	requests chan string
	mu       sync.Mutex
	attempts map[string]attempt
}

func NewWorker(db Publisher, fetcher *Fetcher, interval time.Duration) *Worker {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &Worker{db: db, fetcher: fetcher, interval: interval, started: time.Now(),
		requests: make(chan string, 16), attempts: make(map[string]attempt)}
}

func (w *Worker) Trigger(source string) error {
	state := w.db.Snapshot()
	if s, ok := state.Desired.Subscriptions[source]; !ok || !s.Enabled {
		return fmt.Errorf("unknown or disabled subscription")
	}
	select {
	case w.requests <- source:
		return nil
	default:
		return fmt.Errorf("subscription refresh queue is full")
	}
}

func (w *Worker) Status() []SourceStatus {
	state := w.db.Snapshot()
	w.mu.Lock()
	defer w.mu.Unlock()
	result := make([]SourceStatus, 0, len(state.Desired.Subscriptions))
	for _, id := range slices.Sorted(maps.Keys(state.Desired.Subscriptions)) {
		source := state.Desired.Subscriptions[id]
		artifact, have := state.Artifacts[id]
		a := w.attempts[id]
		s := SourceStatus{ID: id, Digest: artifact.Digest, Rules: artifact.RuleCount,
			LastGood: artifact.FetchedAt, Attempt: a.start, Duration: a.duration, Failures: a.failures, Error: a.error}
		switch {
		case !source.Enabled:
			s.State = "disabled"
		case !have:
			s.State = "staged"
		case artifact.Source != source || a.error != "":
			s.State = "retaining last good"
		default:
			s.State = "active"
		}
		result = append(result, s)
	}
	return result
}

func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		state := w.db.Snapshot()
		w.mu.Lock()
		for id := range w.attempts {
			if _, exists := state.Desired.Subscriptions[id]; !exists {
				delete(w.attempts, id)
			}
		}
		w.mu.Unlock()
		for _, id := range slices.Sorted(maps.Keys(state.Desired.Subscriptions)) {
			s := state.Desired.Subscriptions[id]
			if s.Enabled && !time.Now().Before(w.next(id, s, state.Artifacts[id])) {
				w.refresh(ctx, id, s)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case id := <-w.requests:
			if source := w.db.Snapshot().Desired.Subscriptions[id]; source.Enabled {
				w.refresh(ctx, id, source)
			}
		}
	}
}

func stagger(id string, window time.Duration) time.Duration {
	if window < time.Second {
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(id))
	return time.Duration(h.Sum64() % uint64(window))
}

func (w *Worker) next(id string, source config.Subscription, a config.Artifact) time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	if last := w.attempts[id]; !last.next.IsZero() && last.source == source {
		return last.next
	}
	if a.Source != source || a.FetchedAt.IsZero() {
		return w.started.Add(stagger(id, min(w.interval/10, 20*time.Second)))
	}
	target := a.FetchedAt.Add(w.interval)
	if target.Before(w.started) {
		target = w.started
	}
	return target.Add(stagger(id, min(w.interval/10, 5*time.Minute)))
}

func (w *Worker) refresh(ctx context.Context, id string, source config.Subscription) {
	old, _ := w.db.ReadArtifact(id)
	start := time.Now().UTC()
	a, err := w.fetcher.Fetch(ctx, source, old)
	if err == nil {
		_, err = w.db.Update(ctx, 0, func(state *config.State) error {
			if now, exists := state.Desired.Subscriptions[id]; !exists || now != source {
				return fmt.Errorf("subscription changed during refresh")
			}
			if state.Artifacts == nil {
				state.Artifacts = make(map[string]config.Artifact)
			}
			state.Artifacts[id] = a
			return nil
		})
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	last := w.attempts[id]
	last.start, last.duration, last.source = start, time.Since(start), source
	if err != nil {
		last.error = err.Error()
		last.failures++
		last.streak = min(last.streak+1, 6)
		last.next = time.Now().Add(time.Minute << (last.streak - 1))
	} else {
		last.error = ""
		last.streak = 0
		last.next = start.Add(w.interval + stagger(id, min(w.interval/10, 5*time.Minute)))
	}
	w.attempts[id] = last
}
