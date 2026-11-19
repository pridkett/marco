package main

import (
	"bufio"
	"context"
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
	goruntime "runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
	"github.com/pridkett/marco/internal/dnsserver"
	"github.com/pridkett/marco/internal/filter"
	"github.com/pridkett/marco/internal/querylog"
	"github.com/pridkett/marco/internal/runtime"
	"github.com/pridkett/marco/internal/store"
)

// TestResourceSoak is an opt-in, same-host workload using real UDP, HTTPS, and SQLite.
func TestResourceSoak(t *testing.T) {
	window := os.Getenv("MARCO_SOAK")
	if window == "" {
		t.Skip("set MARCO_SOAK=15m to run the resource workload")
	}
	duration, err := time.ParseDuration(window)
	if err != nil || duration < 6*time.Second {
		t.Fatal("MARCO_SOAK must be a duration of at least 6s")
	}
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), duration+time.Minute)
	defer cancel()
	https := httptest.NewTLSServer(http.HandlerFunc(soakUpstream))
	defer https.Close()
	cert := filepath.Join(root, "upstream.pem")
	writeTestFile(t, cert, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: https.Certificate().Raw})))
	desired := config.Defaults()
	desired.Pools = map[string][]config.Endpoint{"benchmark": {{Transport: "doh", URL: https.URL}}}
	desired.Zones = []config.Zone{{Name: "home.arpa", Private: true, Publish: true}}
	desired.Subscriptions = map[string]config.Subscription{"benchmark": {Enabled: true, File: "filter.txt"}}
	db, err := store.Open(ctx, root, desired)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	compiler, err := newCompiler(config.Deployment{Upstream: config.UpstreamSettings{CAFile: cert}, ListDir: root})
	if err != nil {
		t.Fatal(err)
	}
	p, err := runtime.Open(ctx, db, compiler)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	history, err := querylog.Open(filepath.Join(root, "history.db"), querylog.Settings{Enabled: true, Queue: 16384})
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()
	server, err := dnsserver.Listen(dnsserver.Options{Address: "127.0.0.1:0", Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		View: p.View, Observe: history.Observe})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)
	fresh := soakRSS(t)
	_, err = p.Update(ctx, p.Revision(), func(s *config.State) error {
		now := time.Now().UTC()
		s.Devices = make(map[string]config.Device, 250)

		for i := 0; i < 250; i++ {
			id := fmt.Sprintf("device-%03d", i)
			s.Devices[id] = config.Device{ID: id, Canonical: id, Controller: "benchmark", Site: "lab",
				Connected: true, LastPoll: now, Addresses: []config.Address{{IP: netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}),
					LastSeen: now, Active: true, Publish: true}}}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	list := filepath.Join(root, "filter.txt")
	replace := filepath.Join(root, "replacement.txt")
	soakList(t, list, "old")
	soakList(t, replace, "new")
	worker := filter.NewWorker(p, filter.NewFetcher(root), time.Hour)
	workerCtx, stopWorker := context.WithCancel(ctx)
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); worker.Run(workerCtx) }()
	defer func() { stopWorker(); <-workerDone }()
	if err := worker.Trigger("benchmark"); err != nil {
		t.Fatal(err)
	}
	for {
		if status := worker.Status()[0]; status.State == "active" && status.Rules == 500000 {
			break
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			t.Fatalf("initial benchmark list did not activate: %+v", worker.Status())
		}
	}
	initialDigest := worker.Status()[0].Digest
	for i := 0; i < 10000; i++ {
		history.Observe(contract.Event{Input: contract.Input{Time: time.Now().Add(-time.Hour),
			Name: "prefill.home.arpa.", Peer: netip.MustParseAddr("127.0.0.1"), Type: dns.TypeA}, Result: contract.Result{Origin: "local"}})
	}
	query := new(dns.Msg).SetQuestion("cache.benchmark.test.", dns.TypeA)
	warmClient := dns.Client{Net: "udp", Timeout: time.Second}
	reply, _, err := warmClient.Exchange(query, server.Address())
	if err != nil || len(reply.Answer) != 1 {
		t.Fatalf("warm upstream cache: %v %v", reply, err)
	}
	time.Sleep(time.Second)
	steady, peak, refreshPeak := soakRSS(t), int64(0), int64(0)
	cpuStart := soakCPU(t)
	samples := make(chan soakSample, 4096)
	requests := make(chan uint64, 2048)
	var clients sync.WaitGroup
	for range 32 {
		clients.Go(func() { soakClient(server.Address(), requests, samples) })
	}
	collected := make(chan soakSamples, 1)
	go func() {
		var totals soakSamples
		for result := range samples {
			switch {
			case result.err != nil:
				totals.failures++
				var timeout net.Error
				if errors.As(result.err, &timeout) && timeout.Timeout() {
					totals.timeouts++
				}
			case result.local:
				totals.local = append(totals.local, result.latency)
			default:
				totals.cache = append(totals.cache, result.latency)
			}
		}
		collected <- totals
	}()
	// Sample RSS about every quarter second through the refresh and each second otherwise.
	baseTick := time.NewTicker(4 * time.Millisecond)
	defer baseTick.Stop()
	sampleTick := time.NewTicker(250 * time.Millisecond)
	defer sampleTick.Stop()
	start := time.Now()
	refreshStart, refreshEnd := time.Time{}, time.Time{}
	var sent, generationDrops uint64
	var lastSample time.Time
	burstAt := duration / 2
	burstDuration := min(30*time.Second, duration/3)
running:
	for {
		select {
		case tick := <-baseTick.C:
			elapsed := tick.Sub(start)
			if elapsed >= duration {
				break running
			}
			batch := 1
			if elapsed >= burstAt && elapsed < burstAt+burstDuration {
				batch = 4
				if refreshStart.IsZero() {
					if err := os.Rename(replace, list); err != nil {
						t.Error(err)
						break running
					}
					refreshStart = time.Now()
					if err := worker.Trigger("benchmark"); err != nil {
						t.Error(err)
						break running
					}
				}
			}
			for range batch {
				select {
				case requests <- sent:
					sent++
				default:
					generationDrops++
				}
			}
		case now := <-sampleTick.C:
			refreshing := !refreshStart.IsZero() && refreshEnd.IsZero()
			if refreshing || now.Sub(lastSample) >= time.Second {
				rss := soakRSS(t)
				peak = max(peak, rss)
				lastSample = now
				if refreshing {
					refreshPeak = max(refreshPeak, rss)
					if status := worker.Status()[0]; status.State == "active" && status.Digest != initialDigest {
						refreshEnd = now
					}
				}
			}
		case <-ctx.Done():
			t.Error(ctx.Err())
			break running
		}
	}
	close(requests)
	clients.Wait()
	close(samples)
	totals := <-collected
	elapsed := time.Since(start)
	cpu := soakCPU(t) - cpuStart
	stats := history.Stats()
	endpoint := p.View().Upstream.(*forwarder).Status()[0]
	t.Logf("duration=%v queries=%d qps=%.1f local-p95=%v cached-p95=%v cpu=%.1f%% fresh-rss=%.1fMiB loaded-rss=%.1fMiB peak-rss=%.1fMiB refresh-peak-rss=%.1fMiB",
		elapsed.Round(time.Millisecond), sent, float64(sent)/elapsed.Seconds(), soakP95(totals.local), soakP95(totals.cache),
		100*cpu.Seconds()/elapsed.Seconds(), float64(fresh)/1024, float64(steady)/1024, float64(peak)/1024, float64(refreshPeak)/1024)
	t.Logf("refresh=%v DNS-errors=%d DNS-timeouts=%d generator-drops=%d history-drops=%d cache-hits=%d last-upstream-latency=%v",
		refreshEnd.Sub(refreshStart).Round(time.Millisecond), totals.failures, totals.timeouts,
		generationDrops, stats.Dropped, stats.Total.Cache, endpoint.Latency)
	if refreshEnd.IsZero() || totals.failures != 0 || stats.Total.Cache == 0 {
		t.Fatalf("workload failed; list status %+v", worker.Status())
	}
}

type soakSample struct {
	local   bool
	latency time.Duration
	err     error
}

type soakSamples struct {
	local, cache       []time.Duration
	failures, timeouts int
}

func soakClient(address string, requests <-chan uint64, results chan<- soakSample) {
	target, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		results <- soakSample{err: err}
		return
	}
	socket, err := net.DialUDP("udp", nil, target)
	if err != nil {
		results <- soakSample{err: err}
		return
	}
	defer socket.Close()
	wire := &dns.Conn{Conn: socket}
	client := dns.Client{Net: "udp", Timeout: 500 * time.Millisecond}
	for n := range requests {
		name := "cache.benchmark.test."
		local := n%2 == 0
		if local {
			name = fmt.Sprintf("device-%03d.home.arpa.", n/2%250)
		}
		request := new(dns.Msg).SetQuestion(name, dns.TypeA)
		start := time.Now()
		answer, _, err := client.ExchangeWithConn(request, wire)
		elapsed := time.Since(start)
		if err == nil && (answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1) {
			err = fmt.Errorf("unexpected DNS result")
		}
		results <- soakSample{local: local, latency: elapsed, err: err}
	}
}

func soakUpstream(w http.ResponseWriter, r *http.Request) {
	msg := new(dns.Msg)
	data, err := io.ReadAll(io.LimitReader(r.Body, dns.MaxMsgSize+1))
	if err != nil || len(data) > dns.MaxMsgSize || msg.Unpack(data) != nil || len(msg.Question) != 1 {
		http.Error(w, "invalid fixture query", http.StatusBadRequest)
		return
	}
	q := msg.Question[0]
	msg.SetReply(msg)
	msg.RecursionAvailable = true
	msg.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(198, 51, 100, 1)}}
	wire, err := msg.Pack()
	if err != nil {
		http.Error(w, "invalid fixture response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(wire)
}

func soakList(t *testing.T, path, tag string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := bufio.NewWriter(f)
	for i := 0; i < 500000; i++ {
		if _, err := fmt.Fprintf(buf, "||entry-%06d.%s.fixture.test^\n", i, tag); err != nil {
			t.Fatal(err)
		}
	}
	if err := buf.Flush(); err != nil {
		t.Fatal(err)
	}
}

func soakRSS(t *testing.T) int64 {
	t.Helper()
	if goruntime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/self/statm"); err == nil {
			fields := strings.Fields(string(data))
			if len(fields) >= 2 {
				if pages, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					return pages * int64(os.Getpagesize()) / 1024
				}
			}
		}
	}
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	if goruntime.GOOS == "darwin" {
		return int64(usage.Maxrss) / 1024
	}
	return int64(usage.Maxrss)
}

func soakCPU(t *testing.T) time.Duration {
	t.Helper()
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	return time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
}

func soakP95(sample []time.Duration) time.Duration {
	if len(sample) == 0 {
		return 0
	}
	slices.Sort(sample)
	return sample[(len(sample)-1)*95/100]
}
