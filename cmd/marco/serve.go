package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/pridkett/marco/internal/admin"
	"github.com/pridkett/marco/internal/auth"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
	"github.com/pridkett/marco/internal/dnsserver"
	"github.com/pridkett/marco/internal/filter"
	"github.com/pridkett/marco/internal/inventory"
	"github.com/pridkett/marco/internal/localdns"
	"github.com/pridkett/marco/internal/policy"
	"github.com/pridkett/marco/internal/querylog"
	"github.com/pridkett/marco/internal/runtime"
	"github.com/pridkett/marco/internal/store"
)

func serve(ctx context.Context, d config.Deployment) error {
	lock, err := store.Lock(d.DataDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	state, err := readState(ctx, d)
	if err != nil {
		return err
	}
	compile, err := newCompiler(d)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(d.DataDir, store.StateFile)); errors.Is(err, os.ErrNotExist) {
		view, err := compile(&state, nil)
		if err != nil {
			return err
		}
		view.Upstream.(*forwarder).Close()
	}
	db, err := store.Open(ctx, d.DataDir, state.Desired)
	if err != nil {
		return err
	}
	defer db.Close()
	blocking, err := db.OpenBlocking(ctx)
	if err != nil {
		return fmt.Errorf("load DNS blocking state: %w", err)
	}
	p, err := runtime.Open(ctx, db, compile)
	if err != nil {
		return err
	}
	defer p.Close()

	history, historyErr := openHistory(d)
	if historyErr != nil {
		slog.Warn("query history unavailable", "error", historyErr)
		history, _ = querylog.Open("", querylog.Settings{})
	}
	defer history.Close()

	var listeners []*dnsserver.Server
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, listener := range listeners {
			if err := listener.Shutdown(closeCtx); err != nil {
				slog.Warn("close DNS listener", "error", err)
			}
		}
	}()
	for _, bind := range d.DNS.Listen {
		server, err := dnsserver.Listen(dnsserver.Options{Address: bind, Allow: d.DNS.Allow,
			MaxUDPSize: d.DNS.MaxUDPSize, Concurrency: d.DNS.Concurrency, Node: d.Node, View: p.View,
			Observe: history.Observe, Blocking: blocking.Status})
		if err != nil {
			return fmt.Errorf("DNS listen %s: %w", bind, err)
		}
		listeners = append(listeners, server)
		slog.Info("DNS listening", "node", d.Node, "address", server.Address(), "revision", p.Revision())
	}
	ready := func() bool {
		for _, server := range listeners {
			if !server.Ready() {
				return false
			}
		}
		return true
	}
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		workers.Wait()
	}()
	lists := filter.NewWorker(p, filter.NewFetcher(d.ListDir), time.Duration(d.ListInterval))
	workers.Go(func() { lists.Run(ctx) })
	unifi, unifiErr := newUniFi(d.UniFi, p.Update)
	if unifiErr != nil {
		slog.Warn("UniFi integration unavailable", "error", unifiErr)
	}
	if unifi != nil {
		workers.Go(func() { unifi.Run(ctx) })
	}
	if d.Admin.Listen != "" {
		var authNote string
		authManager, err := openAuth(ctx, db, d.Admin)
		if err != nil {
			authNote = err.Error()
			slog.Warn("admin sign-in degraded", "error", err)
		}
		hooks := admin.Hooks{
			ManagementAPI: d.Admin.ManagementAPI, ManagementMaxPageSize: d.Admin.ManagementMaxPageSize,
			Version: version, Catalog: d.Catalog,
			Snapshot: p.Snapshot, Update: p.Update, Ready: ready, Revision: p.Revision, Refresh: lists.Trigger,
		}
		hooks.Blocking, hooks.SetBlocking = blocking.Status, blocking.Set
		hooks.MatchService = func(id, name string, qtype uint16) filter.Match {
			return p.View().Policies.(*policy.Engine).ServiceMatch(id, name, qtype)
		}
		hooks.Preview = func(in contract.Input) (contract.Selection, contract.Result) {
			if !admitted(d.DNS.Allow, in.Peer) {
				return contract.Selection{}, contract.Result{RCode: dns.RcodeRefused, Reason: "source-not-admitted", Origin: "policy"}
			}
			in.BlockingPaused = blocking.Status(in.Time).Paused
			return dnsserver.Preview(p.View(), in)
		}
		hooks.Select = func(ip netip.Addr, at time.Time) contract.Selection { return p.View().Policies.Select(ip, at) }
		hooks.Lookup = func(name string, qtype uint16) contract.LocalResult { return p.View().Local.Lookup(name, qtype) }
		hooks.Published = func(id string) bool { return p.View().Local.(*localdns.View).Published(id) }
		hooks.LocalIssues = func() any { return p.View().Local.(*localdns.View).Issues() }
		if unifi != nil {
			hooks.Poll = func() error { unifi.Trigger(); return nil }
		}
		hooks.TestUpstream = func(ctx context.Context, pool string) (any, error) {
			return testPool(ctx, p.View().Upstream.(*forwarder), pool)
		}
		hooks.Status = func() any {
			var mem goruntime.MemStats
			goruntime.ReadMemStats(&mem)
			v := p.View()
			status := map[string]any{
				"node": d.Node, "revision": v.Revision, "DNS ready": ready(), "heap bytes": mem.Alloc,
				"upstreams": v.Upstream.(*forwarder).Status(), "subscriptions": lists.Status(),
				"publication issues": v.Local.(*localdns.View).Issues(),
			}
			switch {
			case unifi != nil:
				status["UniFi"] = unifi.Status()
			case unifiErr != nil:
				status["UniFi"] = unifiErr.Error()
			default:
				status["UniFi"] = "disabled"
			}
			if historyErr != nil {
				status["history"] = historyErr.Error()
			}
			if authNote != "" {
				status["sign-in"] = authNote
			}
			return status
		}
		httpServer, err := startAdmin(ctx, d.Admin, admin.New(authManager, history, hooks))
		if err != nil {
			slog.Warn("admin HTTP unavailable", "error", err)
		}
		if httpServer != nil {
			defer func() {
				closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer closeCancel()
				if err := httpServer.Shutdown(closeCtx); err != nil {
					httpServer.Close()
				}
			}()
		}
	}
	<-ctx.Done()
	return nil
}

func openHistory(d config.Deployment) (*querylog.Log, error) {
	key, err := d.History.AnonymizationKey.Resolve("history anonymization key")
	if err != nil && d.History.Enabled && d.History.Anonymize {
		return nil, err
	}
	path := filepath.Join(d.DataDir, store.HistoryFile)
	if d.History.Enabled {
		file, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0600)
		if err != nil {
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
	}
	return querylog.Open(path, querylog.Settings{Enabled: d.History.Enabled, Anonymize: d.History.Anonymize,
		Queue: d.History.Queue, MaxBytes: d.History.MaxBytes, Retention: time.Duration(d.History.Retention), AnonymizationKey: []byte(key)})
}

func admitted(allow []netip.Prefix, peer netip.Addr) bool {
	for _, prefix := range allow {
		if prefix.Contains(peer.Unmap()) {
			return true
		}
	}
	return false
}

func newUniFi(s config.UniFiSettings, update contract.Update) (*inventory.Worker, error) {
	if s.URL == "" {
		return nil, nil
	}
	key, err := s.APIKey.Resolve("UniFi API key")
	if err != nil {
		return nil, err
	}
	password, err := s.Password.Resolve("UniFi password")
	if err != nil {
		return nil, err
	}
	source, err := inventory.NewAdapter(inventory.Settings{Controller: s.Controller, URL: s.URL, Site: s.Site, Mode: s.Mode,
		APIKey: key, Username: s.Username, Password: password, CACertFile: s.CAFile, PageSize: s.PageSize, DialIP: s.DialIP})
	if err != nil {
		return nil, err
	}
	return inventory.NewWorker(source, update, time.Duration(s.Interval)), nil
}

func localPasswordHash(ctx context.Context, db *store.Store, s config.AdminSettings) (string, error) {
	if value := os.Getenv(config.AdminPasswordEnv); value != "" {
		return auth.ProvisionedPasswordHash(ctx, db, value)
	}
	if s.Password.Set() {
		value, err := s.Password.Resolve("local admin password")
		if err != nil {
			return "", err
		}
		return auth.ProvisionedPasswordHash(ctx, db, value)
	}
	return s.PasswordHash.Resolve("local admin password hash")
}

func openAuth(ctx context.Context, db *store.Store, s config.AdminSettings) (*auth.Manager, error) {
	hash, localErr := localPasswordHash(ctx, db, s)
	secret, oidcErr := s.ClientSecret.Resolve("OIDC client secret")
	settings := auth.Settings{PublicURL: s.PublicURL, TrustedProxies: s.TrustedProxies, SessionTTL: time.Duration(s.SessionTTL)}
	if localErr == nil && hash != "" {
		settings.Username, settings.PasswordHash = s.LocalUsername(), hash
	}
	if oidcErr == nil {
		settings.Issuer, settings.ClientID, settings.ClientSecret, settings.AdminGroup = s.Issuer, s.ClientID, secret, s.AdminGroup
	}
	manager, err := auth.New(ctx, db, settings)
	if err != nil && settings.Username != "" && settings.Issuer != "" {
		localOnly := settings
		localOnly.Issuer, localOnly.ClientID, localOnly.ClientSecret, localOnly.AdminGroup = "", "", "", ""
		if localManager, localInitErr := auth.New(ctx, db, localOnly); localInitErr == nil {
			return localManager, fmt.Errorf("OIDC unavailable: %w", err)
		}
		settings.Username, settings.PasswordHash = "", ""
		if oidcManager, oidcInitErr := auth.New(ctx, db, settings); oidcInitErr == nil {
			return oidcManager, fmt.Errorf("local sign-in unavailable: %w", err)
		}
	}
	return manager, errors.Join(localErr, oidcErr, err)
}

func startAdmin(ctx context.Context, s config.AdminSettings, handler http.Handler) (*http.Server, error) {
	server := &http.Server{Addr: s.Listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 32 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	listener, err := net.Listen("tcp", s.Listen)
	if err != nil {
		return nil, err
	}
	server.Addr = listener.Addr().String()
	if s.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
		if err != nil {
			listener.Close()
			return nil, fmt.Errorf("load admin TLS files: %w", err)
		}
		server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	go func() {
		var err error
		if server.TLSConfig != nil {
			err = server.ServeTLS(listener, "", "")
		} else {
			err = server.Serve(listener)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Warn("admin HTTP listener stopped", "error", err)
		}
	}()
	slog.Info("admin HTTP listening", "address", listener.Addr().String())
	return server, nil
}

func testPool(ctx context.Context, forward *forwarder, target string) (any, error) {
	pool := target
	index := -1
	if name, number, ok := strings.Cut(target, ":"); ok {
		n, err := strconv.Atoi(number)
		if err != nil || n < 0 {
			return nil, errors.New("invalid endpoint index")
		}
		pool, index = name, n
	}
	matched := 0
	var problems error
	for _, status := range forward.Status() {
		if status.Pool != pool || index >= 0 && status.Index != index {
			continue
		}
		matched++
		if err := forward.Test(ctx, status.Pool, status.Index); err != nil {
			problems = errors.Join(problems, fmt.Errorf("endpoint %d: %w", status.Index, err))
		}
	}
	if matched == 0 {
		return nil, errors.New("unknown upstream pool or endpoint")
	}
	return forward.Status(), problems
}
