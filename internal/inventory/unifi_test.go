package inventory

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pridkett/marco/internal/config"
)

func certFile(t *testing.T, server *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOfficialAdapterCompletePageAndPartialPoll(t *testing.T) {
	const controllerHost = "unifi.example.com"
	var failPage atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil || host != controllerHost || r.TLS.ServerName != controllerHost {
			t.Errorf("unexpected HTTP host %q or TLS server name %q", r.Host, r.TLS.ServerName)
		}
		if r.Method != http.MethodGet || r.Header.Get("X-API-Key") != "fixture-key" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path + "?" + r.URL.RawQuery {
		case "/proxy/network/integration/v1/sites/fixture/clients?limit=1&offset=0":
			fmt.Fprint(w, `{"offset":0,"limit":1,"count":1,"totalCount":2,"data":[{"id":"c1","macAddress":"02:AA:00:00:00:01","ipAddress":"192.0.2.11","name":"Fixture Client","vlan":12}]}`)
		case "/proxy/network/integration/v1/sites/fixture/clients?limit=1&offset=1":
			if failPage.Load() {
				fmt.Fprint(w, `{"offset":1,"limit":1,"count":0,"totalCount":2,"data":[]}`)
				return
			}
			fmt.Fprint(w, `{"offset":1,"limit":1,"count":1,"totalCount":2,"data":[{"id":"c2","ipAddress":"2001:db8::12","name":"Fixture IPv6"}]}`)
		case "/proxy/network/integration/v1/sites/fixture/devices?limit=1&offset=0":
			fmt.Fprint(w, `{"offset":0,"limit":1,"count":1,"totalCount":1,"data":[{"id":"d1","macAddress":"02:AA:00:00:00:03","ipAddress":"192.0.2.13","name":"Fixture Switch","state":"ONLINE"}]}`)
		default:
			t.Errorf("unexpected pagination: %s", r.URL.RequestURI())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	ip, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cfg := Settings{Controller: "fixture-controller", Site: "fixture",
		URL: "https://" + net.JoinHostPort(controllerHost, port), DialIP: netip.MustParseAddr(ip),
		APIKey: "fixture-key", PageSize: 1, CACertFile: certFile(t, server)}
	a, err := NewAdapter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first, err := a.Poll(t.Context())
	if err != nil || !first.Complete || len(first.Observations) != 3 {
		t.Fatalf("complete snapshot = %+v: %v", first, err)
	}
	if first.Observations[0].MAC != "02:aa:00:00:00:01" || first.Observations[0].Network != "VLAN 12" ||
		!first.Observations[2].Present || !first.Observations[2].UseObservationTime {
		t.Fatalf("bad normalized observations: %+v", first.Observations)
	}
	if first.Observations[1].CompleteIPv4 || first.Observations[1].CompleteIPv6 {
		t.Fatal("a single IPv6 address asserted address-family completeness")
	}
	failPage.Store(true)
	if partial, err := a.Poll(t.Context()); err == nil || partial.Complete || len(partial.Observations) != 0 {
		t.Fatalf("partial snapshot escaped: %+v: %v", partial, err)
	}

	wrongHost := cfg
	wrongHost.URL = "https://" + net.JoinHostPort("unifi.invalid", port)
	wrongName, err := NewAdapter(wrongHost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wrongName.Poll(t.Context()); err == nil || !strings.Contains(err.Error(), "UniFi TLS certificate verification failed") {
		t.Fatalf("fixed dial accepted a certificate for a different hostname: %v", err)
	}

	cfg.CACertFile = ""
	unknownCA, err := NewAdapter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = unknownCA.Poll(t.Context()); err == nil {
		t.Fatal("accepted fixture certificate without its CA")
	}
}

func TestLocalAccountReusesSessionAndHonorsRetryAfter(t *testing.T) {
	var logins atomic.Int32
	var throttled atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			logins.Add(1)
			var credentials map[string]string
			if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil ||
				credentials["username"] != "fixture-local" || credentials["password"] != "fixture-password" {
				t.Errorf("unexpected compatibility sign-in")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "unifi-session", Value: "fixture", Secure: true, Path: "/"})
			w.Header().Set("X-CSRF-Token", "fixture-csrf")
			fmt.Fprint(w, `{}`)
		case "/proxy/network/api/s/default/stat/sta", "/proxy/network/api/s/default/stat/device":
			if r.Method != http.MethodGet {
				t.Errorf("compatibility poll used %s", r.Method)
			}
			if _, err := r.Cookie("unifi-session"); err != nil || r.Header.Get("X-CSRF-Token") != "fixture-csrf" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if throttled.Load() {
				w.Header().Set("Retry-After", "1800")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			if r.URL.Path == "/proxy/network/api/s/default/stat/device" {
				fmt.Fprint(w, `{"meta":{"rc":"ok"},"data":[{"mac":"02:AA:00:00:00:04","ip":"192.0.2.44","name":"Offline AP","state":0}]}`)
			} else {
				fmt.Fprint(w, `{"meta":{"rc":"ok"},"data":[{"mac":"02:AA:00:00:00:01","ip":"192.0.2.11","hostname":"fixture-client"}]}`)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	a, err := NewAdapter(Settings{Controller: "fixture-controller", Site: "default", URL: server.URL,
		Mode: "local-account", CACertFile: certFile(t, server), Username: "fixture-local", Password: "fixture-password"})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		snapshot, err := a.Poll(t.Context())
		if err != nil || !snapshot.Complete || len(snapshot.Observations) != 2 {
			t.Fatalf("compatibility snapshot = %+v: %v", snapshot, err)
		}
		if snapshot.Observations[1].Present || snapshot.Observations[1].UseObservationTime {
			t.Fatal("an offline infrastructure row acquired current presence")
		}
	}
	if logins.Load() != 1 {
		t.Fatalf("local login count = %d", logins.Load())
	}
	throttled.Store(true)
	var status *HTTPError
	partial, err := a.Poll(t.Context())
	if partial.Complete || !errors.As(err, &status) || status.Status != http.StatusTooManyRequests ||
		status.RetryAfter != 30*time.Minute || backoff(time.Minute, 10, err) != 30*time.Minute {
		t.Fatalf("throttle snapshot = %+v: %v", partial, err)
	}
}

type fixtureAdapter struct {
	snapshot Snapshot
	err      error
}

func (f *fixtureAdapter) Poll(context.Context) (Snapshot, error) {
	return f.snapshot, f.err
}

func TestWorkerLeavesPreviousStateOnFailedPoll(t *testing.T) {
	state := config.State{Desired: config.Defaults()}
	source := &fixtureAdapter{snapshot: Snapshot{
		Controller: "fixture-controller", Site: "default", ObservedAt: fixtureTime,
		Complete: true, Observations: []Observation{fixtureRow("02:aa:00:00:00:01", "Fixture", "192.0.2.12")},
	}}
	writes := 0
	worker := NewWorker(source, func(_ context.Context, base uint64, edit func(*config.State) error) (uint64, error) {
		if base != 0 {
			t.Errorf("worker update uses external edit base %d", base)
		}
		writes++
		return uint64(writes), edit(&state)
	}, time.Minute)
	worker.poll(t.Context())
	first := worker.Status()
	source.err = io.ErrUnexpectedEOF
	worker.poll(t.Context())
	failed := worker.Status()
	if writes != 1 || len(state.Devices) != 1 || failed.LastSuccess != first.LastSuccess ||
		!failed.Unavailable || failed.Failures != 1 || failed.Revision != first.Revision {
		t.Fatalf("failed poll mutated the last accepted snapshot: %+v / %+v", first, failed)
	}
}
