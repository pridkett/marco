package inventory

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
)

type Status struct {
	Controller  string        `json:"controller,omitempty"`
	Site        string        `json:"site,omitempty"`
	Polling     bool          `json:"polling"`
	Unavailable bool          `json:"unavailable"`
	LastAttempt time.Time     `json:"lastAttempt,omitempty"`
	LastSuccess time.Time     `json:"lastSuccess,omitempty"`
	NextAttempt time.Time     `json:"nextAttempt,omitempty"`
	Duration    time.Duration `json:"duration"`
	Failures    int           `json:"failures"`
	Rows        int           `json:"rows"`
	Revision    uint64        `json:"revision,omitempty"`
	Error       string        `json:"error,omitempty"`
}

type Worker struct {
	adapter  Adapter
	update   contract.Update
	interval time.Duration
	trigger  chan struct{}
	mu       sync.Mutex
	status   Status
}

func NewWorker(source Adapter, update contract.Update, interval time.Duration) *Worker {
	if interval <= 0 {
		interval = time.Minute
	}
	status := Status{Unavailable: true}
	if a, ok := source.(*adapter); ok {
		status.Controller, status.Site = a.c.Controller, a.c.Site
	}
	return &Worker{adapter: source, update: update, interval: interval, trigger: make(chan struct{}, 1), status: status}
}

func (w *Worker) Trigger() {
	select {
	case w.trigger <- struct{}{}:
	default:
	}
}

func (w *Worker) Status() Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}

func backoff(interval time.Duration, failures int, err error) time.Duration {
	base := min(interval, 15*time.Minute)
	for i := 1; i < failures && base < 15*time.Minute; i++ {
		base = min(15*time.Minute, base*2)
	}
	// Keep a small jitter range while respecting the configured backoff cap.
	delay := min(15*time.Minute, base/2+base/4+time.Duration(rand.Int64N(max(1, int64(base/2)))))
	var response *HTTPError
	if errors.As(err, &response) {
		delay = max(delay, response.RetryAfter)
	}
	return delay
}

func (w *Worker) poll(ctx context.Context) (time.Duration, bool) {
	start := time.Now()
	w.mu.Lock()
	w.status.LastAttempt, w.status.Polling = start.UTC(), true
	w.mu.Unlock()
	attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	snapshot, err := w.adapter.Poll(attempt)
	var revision uint64
	if err == nil {
		revision, err = w.update(attempt, 0, func(candidate *config.State) error {
			return Reconcile(candidate, snapshot)
		})
	}

	finish := time.Now()
	delay := w.interval
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status.Polling, w.status.Duration = false, finish.Sub(start)
	w.status.Unavailable = err != nil
	if err == nil {
		w.status.Controller, w.status.Site = snapshot.Controller, snapshot.Site
		w.status.LastSuccess, w.status.Rows, w.status.Revision = finish.UTC(), len(snapshot.Observations), revision
		w.status.Failures, w.status.Error = 0, ""
	} else {
		w.status.Failures++
		w.status.Error = err.Error()
		delay = backoff(w.interval, w.status.Failures, err)
	}
	w.status.NextAttempt = finish.Add(delay).UTC()
	return delay, err != nil
}

func (w *Worker) Run(ctx context.Context) {
	if source, ok := w.adapter.(interface{ CloseIdleConnections() }); ok {
		defer source.CloseIdleConnections()
	}
	for ctx.Err() == nil {
		delay, coolingDown := w.poll(ctx)
		timer := time.NewTimer(delay)
		wait := true
		for wait {
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				wait = false
			case <-w.trigger:
				if !coolingDown {
					wait = false
				}
			}
		}
		timer.Stop()
	}
}
