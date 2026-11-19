// Package runtime publishes a validated immutable DNS view after committing durable state.
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"sync/atomic"

	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
	"github.com/pridkett/marco/internal/store"
)

type Compiler func(state *config.State, previous *contract.View) (*contract.View, error)

type snapshot struct {
	state config.State
	view  *contract.View
}

type Publisher struct {
	store *store.Store
	build Compiler
	lock  chan struct{}
	queue chan struct{}
	live  atomic.Pointer[snapshot]
}

func Open(ctx context.Context, db *store.Store, build Compiler) (*Publisher, error) {
	state, err := db.Load(ctx)
	if err != nil {
		return nil, err
	}
	view, err := build(&state, nil)
	if err != nil {
		return nil, fmt.Errorf("compile revision %d: %w", state.Revision, err)
	}
	view.Revision = state.Revision
	p := &Publisher{store: db, build: build, lock: make(chan struct{}, 1), queue: make(chan struct{}, 16)}
	p.live.Store(&snapshot{state, view})
	return p, nil
}

func (p *Publisher) View() *contract.View { return p.live.Load().view }
func (p *Publisher) Revision() uint64     { return p.View().Revision }

// Snapshot excludes the list bodies, which can be very large and are never needed by the console.
func (p *Publisher) Snapshot() config.State {
	state, err := clone(p.live.Load().state)
	if err != nil {
		panic(err) // A published state has already been encoded successfully.
	}
	for source, artifact := range state.Artifacts {
		artifact.Body = nil
		state.Artifacts[source] = artifact
	}
	return state
}

// Update uses base=0 only for transactional workers. External callers must send their base revision.
// Artifact bodies are immutable. A change replaces an entire artifact instead of editing its bytes.
func (p *Publisher) Update(ctx context.Context, base uint64, change func(*config.State) error) (uint64, error) {
	select {
	case p.queue <- struct{}{}:
	default:
		return p.Revision(), store.ErrBusy
	}
	defer func() { <-p.queue }()
	select {
	case p.lock <- struct{}{}:
	case <-ctx.Done():
		return p.Revision(), ctx.Err()
	}
	defer func() { <-p.lock }()
	old := p.live.Load()
	if base != 0 && old.state.Revision != base {
		return old.state.Revision, fmt.Errorf("%w: current revision is %d", store.ErrStale, old.state.Revision)
	}
	next, err := clone(old.state)
	if err != nil {
		return old.state.Revision, err
	}
	if err := change(&next); err != nil {
		return old.state.Revision, err
	}
	if reflect.DeepEqual(old.state, next) {
		return old.state.Revision, nil
	}
	next.Revision = old.state.Revision + 1
	view, err := p.build(&next, old.view)
	if err != nil {
		return old.state.Revision, err
	}
	view.Revision = next.Revision
	if err := p.store.Save(ctx, old.state, next); err != nil {
		closeUpstream(view.Upstream, old.view.Upstream)
		return old.state.Revision, err
	}
	p.live.Store(&snapshot{next, view})
	closeUpstream(old.view.Upstream, view.Upstream)
	return next.Revision, nil
}

// ReadArtifact returns immutable artifact data to the subscription worker.
func (p *Publisher) ReadArtifact(source string) (config.Artifact, bool) {
	a, ok := p.live.Load().state.Artifacts[source]
	return a, ok
}

func clone(state config.State) (config.State, error) {
	artifacts := maps.Clone(state.Artifacts)
	state.Artifacts = nil
	data, err := json.Marshal(state)
	if err != nil {
		return config.State{}, err
	}
	var copy config.State
	if err := json.Unmarshal(data, &copy); err != nil {
		return config.State{}, err
	}
	copy.Artifacts = artifacts
	return copy, nil
}

// Close releases idle transport resources after the listeners and workers have stopped.
func (p *Publisher) Close() { closeUpstream(p.View().Upstream, nil) }

func closeUpstream(retired, active contract.Upstream) {
	closer, ok := retired.(interface{ Close() })
	if ok && !sameUpstream(retired, active) {
		closer.Close()
	}
}

func sameUpstream(left, right contract.Upstream) bool {
	t := reflect.TypeOf(left)
	return t != nil && t == reflect.TypeOf(right) && t.Comparable() && left == right
}
