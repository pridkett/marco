package filter

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/pridkett/marco/internal/config"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestConditionalFetchAndRedirectGuard(t *testing.T) {
	fetcher := NewFetcher("")
	source := config.Subscription{Enabled: true, URL: "https://public.example/filter"}
	calls := 0
	fetcher.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "public.example" {
			t.Fatalf("made an unvalidated redirect request to %s", r.URL.Host)
		}
		reply := &http.Response{Header: make(http.Header), Body: http.NoBody, Request: r}
		switch calls {
		case 1:
			reply.StatusCode = http.StatusOK
			reply.Body = io.NopCloser(strings.NewReader("||blocked.test^\n"))
			reply.Header.Set("ETag", `"fixture"`)
			reply.Header.Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
		case 2:
			if r.Header.Get("If-None-Match") != `"fixture"` || r.Header.Get("If-Modified-Since") == "" {
				t.Fatal("missing conditional fetch headers")
			}
			reply.StatusCode = http.StatusNotModified
		default:
			reply.StatusCode = http.StatusFound
			reply.Header.Set("Location", "https://127.0.0.1/private")
		}
		return reply, nil
	})
	first, err := fetcher.Fetch(context.Background(), source, config.Artifact{})
	if err != nil || first.Digest == "" {
		t.Fatalf("initial fetch: %+v %v", first, err)
	}
	second, err := fetcher.Fetch(context.Background(), source, first)
	if err != nil || second.Digest != first.Digest || string(second.Body) != string(first.Body) {
		t.Fatalf("304 refresh: %+v %v", second, err)
	}
	if _, err := fetcher.Fetch(context.Background(), source, second); err == nil || calls != 3 {
		t.Fatalf("redirect was accepted: %v, requests=%d", err, calls)
	}
	for _, address := range []string{"10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "192.0.0.1", "198.18.0.1", "::1", "fc00::1", "2001:db8::1", "::ffff:127.0.0.1"} {
		if public(netip.MustParseAddr(address)) {
			t.Fatalf("accepted a non-public dial address %s", address)
		}
	}
}
