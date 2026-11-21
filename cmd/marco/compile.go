package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
	"github.com/pridkett/marco/internal/localdns"
	"github.com/pridkett/marco/internal/policy"
	"github.com/pridkett/marco/internal/runtime"
	"github.com/pridkett/marco/internal/upstream"
)

type forwarder struct {
	*upstream.Pools
	generation [32]byte
}

func newCompiler(deployment config.Deployment) (runtime.Compiler, error) {
	s := deployment.Upstream
	var roots *x509.CertPool
	if s.CAFile != "" {
		data, err := os.ReadFile(s.CAFile)
		if err != nil {
			return nil, fmt.Errorf("upstream CA: %w", err)
		}
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system CA roots: %w", err)
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("upstream CA file contains no usable certificates")
		}
	}
	options := upstream.Options{Deadline: time.Duration(s.Deadline), CacheEntries: s.CacheEntries,
		CacheTTL: time.Duration(s.CacheTTL), MaxConnections: s.MaxConnections, BootstrapResolver: s.Resolver(), TLSRoots: roots}
	builtIn := deployment.Catalog.Definitions()
	return func(state *config.State, previous *contract.View) (*contract.View, error) {
		d := state.Desired
		if len(builtIn) > 0 {
			d.Services = maps.Clone(builtIn)
			maps.Copy(d.Services, state.Desired.Services)
		}
		if d.Version != config.Version {
			return nil, fmt.Errorf("configuration version %d is unsupported", d.Version)
		}
		if err := policy.Validate(d); err != nil {
			return nil, err
		}
		if d.Default.Pool == "" && len(d.Pools) > 1 {
			return nil, errors.New("select a default upstream pool when configuring several pools")
		}
		forwarding, err := compileForwarding(d)
		if err != nil {
			return nil, err
		}
		if err := validateBootstrap(d, options.BootstrapResolver != nil); err != nil {
			return nil, err
		}
		for id, source := range d.Subscriptions {
			if source.Enabled && source.File != "" && deployment.ListDir == "" {
				return nil, fmt.Errorf("subscription %q: configure a provisioned list directory to use local files", id)
			}
		}
		artifactBytes := 0
		for id, artifact := range state.Artifacts {
			if _, ok := d.Subscriptions[id]; !ok {
				delete(state.Artifacts, id)
				continue
			}
			artifactBytes += len(artifact.Body)
		}
		if artifactBytes > 64<<20 {
			return nil, errors.New("retained subscription artifacts exceed 64 MiB")
		}
		local, err := localdns.Compile(state)
		if err != nil {
			return nil, err
		}
		var lastPolicy *policy.Engine
		var lastUpstream *forwarder
		if previous != nil {
			lastPolicy, _ = previous.Policies.(*policy.Engine)
			lastUpstream, _ = previous.Upstream.(*forwarder)
		}
		policyState := *state
		policyState.Desired.Services = d.Services
		rules, err := policy.Compile(&policyState, lastPolicy)
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(d.Pools)
		if err != nil {
			return nil, err
		}
		generation := sha256.Sum256(encoded)
		if lastUpstream == nil || lastUpstream.generation != generation {
			pools, err := upstream.New(d.Pools, options)
			if err != nil {
				return nil, err
			}
			lastUpstream = &forwarder{pools, generation}
		}
		return &contract.View{Policies: rules, Local: local, Upstream: lastUpstream, Forwarding: forwarding}, nil
	}, nil
}

func compileForwarding(d config.Desired) (map[string]string, error) {
	if len(d.Forwarding) > 1024 {
		return nil, errors.New("configure at most 1024 forwarding suffixes")
	}
	routes := make(map[string]string, len(d.Forwarding))
	for suffix, pool := range d.Forwarding {
		name, err := config.Name(suffix)
		if err != nil {
			return nil, fmt.Errorf("forwarding suffix: %w", err)
		}
		if _, exists := routes[name]; exists {
			return nil, fmt.Errorf("duplicate forwarding suffix %q", name)
		}
		if len(d.Pools[pool]) == 0 {
			return nil, fmt.Errorf("forwarding suffix %q references unknown upstream pool %q", name, pool)
		}
		routes[name] = pool
	}
	return routes, nil
}

func validateBootstrap(d config.Desired, independent bool) error {
	endpoints := 0
	for pool, specs := range d.Pools {
		endpoints += len(specs)
		if endpoints > 64 || len(specs) > 16 {
			return errors.New("configure at most 64 upstream endpoints and 16 endpoints in one pool")
		}
		for i, spec := range specs {
			if independent || len(spec.Bootstrap) != 0 {
				continue
			}
			host := spec.Address
			if host == "" && strings.EqualFold(spec.Transport, "doh") {
				if u, err := url.Parse(spec.URL); err == nil {
					host = u.Hostname()
				}
			}
			if _, err := netip.ParseAddr(host); err != nil {
				return fmt.Errorf("upstream pool %q endpoint %d requires an IP, bootstrap addresses, or independent bootstrap DNS", pool, i+1)
			}
		}
	}
	return nil
}
