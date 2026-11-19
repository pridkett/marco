package filter

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pridkett/marco/internal/config"
)

type Fetcher struct {
	client *http.Client
	local  string
}

func NewFetcher(directory string) *Fetcher {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext:            dialPublic,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:           4,
			MaxConnsPerHost:        2,
			IdleConnTimeout:        time.Minute,
			DisableKeepAlives:      true,
			MaxResponseHeaderBytes: 32 << 10,
		},
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return validURL(r.URL)
		},
	}
	return &Fetcher{client: client, local: directory}
}

func ValidateSource(s config.Subscription) error {
	if (s.URL == "") == (s.File == "") {
		return fmt.Errorf("specify exactly one HTTPS URL or local file")
	}
	if s.File != "" {
		if s.File == "." || !filepath.IsLocal(s.File) || filepath.Clean(s.File) != s.File || strings.Contains(s.File, "\\") {
			return fmt.Errorf("subscription file must be relative to the provisioned source directory")
		}
		return nil
	}
	u, err := url.Parse(s.URL)
	if err != nil {
		return fmt.Errorf("invalid subscription URL")
	}
	return validURL(u)
}

func validURL(u *url.URL) error {
	if u == nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("subscription URL must use HTTPS with a host and without credentials or a fragment")
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !public(ip) {
		return fmt.Errorf("subscription address is not public")
	}
	return nil
}

var restricted = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}
var globalIPv6 = netip.MustParsePrefix("2000::/3")

func public(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.Zone() != "" || ip.Is6() && !globalIPv6.Contains(ip) {
		return false
	}
	for _, prefix := range restricted {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func dialPublic(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid subscription destination")
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("subscription destination resolution failed")
	}
	for _, ip := range ips {
		if !public(ip) {
			return nil, fmt.Errorf("subscription destination resolves to a non-public address")
		}
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	for _, ip := range ips {
		if conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port)); err == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("could not connect to subscription destination")
}

func (f *Fetcher) Fetch(ctx context.Context, source config.Subscription, previous config.Artifact) (config.Artifact, error) {
	if err := ValidateSource(source); err != nil {
		return config.Artifact{}, err
	}
	artifact := config.Artifact{Source: source, FetchedAt: time.Now().UTC()}
	var reader io.ReadCloser
	if source.File != "" {
		if f.local == "" {
			return artifact, fmt.Errorf("no read-only subscription directory configured")
		}
		root, err := os.OpenRoot(f.local)
		if err != nil {
			return artifact, fmt.Errorf("open subscription directory: %w", err)
		}
		defer root.Close()
		info, err := root.Stat(source.File)
		if err != nil {
			return artifact, err
		}
		if !info.Mode().IsRegular() {
			return artifact, fmt.Errorf("subscription file must be regular")
		}
		file, err := root.Open(source.File)
		if err != nil {
			return artifact, err
		}
		reader = file
	} else {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
		if err != nil {
			return artifact, fmt.Errorf("invalid subscription request")
		}
		if previous.Source == source && previous.Digest != "" {
			request.Header.Set("If-None-Match", previous.ETag)
			request.Header.Set("If-Modified-Since", previous.LastModified)
		}
		response, err := f.client.Do(request)
		if err != nil {
			if u, ok := err.(*url.Error); ok {
				return artifact, fmt.Errorf("download subscription: %w", u.Err)
			}
			return artifact, fmt.Errorf("download subscription failed")
		}
		reader = response.Body
		if response.StatusCode == http.StatusNotModified && previous.Source == source && previous.Digest != "" {
			reader.Close()
			previous.FetchedAt = artifact.FetchedAt
			return previous, nil
		}
		if response.StatusCode != http.StatusOK {
			reader.Close()
			return artifact, fmt.Errorf("subscription host returned HTTP %d", response.StatusCode)
		}
		artifact.ETag = response.Header.Get("ETag")
		artifact.LastModified = response.Header.Get("Last-Modified")
	}
	defer reader.Close()
	body, err := io.ReadAll(io.LimitReader(reader, MaxBytes+1))
	if err != nil {
		return artifact, fmt.Errorf("read subscription: %w", err)
	}
	if ctx.Err() != nil {
		return artifact, ctx.Err()
	}
	_, count, err := Parse(body, source.Allowlist, source.AllowEmpty)
	if err != nil {
		return artifact, err
	}
	artifact.Body = body
	artifact.Digest = fmt.Sprintf("%x", sha256.Sum256(body))
	artifact.RuleCount = count
	return artifact, nil
}
