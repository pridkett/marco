package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Duration time.Duration

func (d *Duration) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return errors.New("use a duration string such as 2s or 24h")
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return errors.New("expected a positive duration")
	}
	*d = Duration(value)
	return nil
}

type SecretRef struct {
	Env  string `json:"env,omitempty"`
	File string `json:"file,omitempty"`
}

func (r SecretRef) Set() bool { return r.Env != "" || r.File != "" }

func (r SecretRef) Resolve(label string) (string, error) {
	switch {
	case r.Env != "" && r.File != "":
		return "", fmt.Errorf("%s: specify one secret reference", label)
	case r.Env != "":
		if value := os.Getenv(r.Env); value != "" {
			return value, nil
		}
	case r.File != "":
		value, err := readBounded(r.File, 16<<10)
		if err != nil {
			return "", fmt.Errorf("%s: cannot read secret file", label)
		}
		if text := strings.TrimRight(string(value), "\r\n"); text != "" {
			return text, nil
		}
	default:
		return "", nil
	}
	return "", fmt.Errorf("%s: secret is empty or unavailable", label)
}

type DNSSettings struct {
	Listen      []string       `json:"listen"`
	Allow       []netip.Prefix `json:"allow"`
	MaxUDPSize  uint16         `json:"maxUDPSize"`
	Concurrency int            `json:"concurrency"`
}

type UpstreamSettings struct {
	Deadline        Duration       `json:"deadline"`
	CacheEntries    int            `json:"cacheEntries"`
	CacheTTL        Duration       `json:"cacheTTL"`
	MaxConnections  int            `json:"maxConnections"`
	BootstrapDNS    netip.AddrPort `json:"bootstrapDNS"`
	SystemBootstrap bool           `json:"systemBootstrap"`
	CAFile          string         `json:"caFile"`
}

func (s UpstreamSettings) Resolver() *net.Resolver {
	if s.BootstrapDNS.IsValid() {
		return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, s.BootstrapDNS.String())
		}}
	}
	if s.SystemBootstrap {
		return net.DefaultResolver
	}
	return nil
}

type AdminSettings struct {
	Listen         string         `json:"listen"`
	PublicURL      string         `json:"publicURL"`
	TrustedProxies []netip.Prefix `json:"trustedProxies"`
	CertFile       string         `json:"certFile"`
	KeyFile        string         `json:"keyFile"`
	Username       string         `json:"username"`
	PasswordHash   SecretRef      `json:"passwordHash"`
	Issuer         string         `json:"issuer"`
	ClientID       string         `json:"clientID"`
	ClientSecret   SecretRef      `json:"clientSecret"`
	AdminGroup     string         `json:"adminGroup"`
	SessionTTL     Duration       `json:"sessionTTL"`
}

type UniFiSettings struct {
	Controller string    `json:"controller"`
	URL        string    `json:"url"`
	Site       string    `json:"site"`
	Mode       string    `json:"mode"`
	APIKey     SecretRef `json:"apiKey"`
	Username   string    `json:"username"`
	Password   SecretRef `json:"password"`
	CAFile     string    `json:"caFile"`
	PageSize   int       `json:"pageSize"`
	Interval   Duration  `json:"interval"`
}

type HistorySettings struct {
	Enabled          bool      `json:"enabled"`
	Anonymize        bool      `json:"anonymize"`
	AnonymizationKey SecretRef `json:"anonymizationKey"`
	Queue            int       `json:"queue"`
	MaxBytes         int64     `json:"maxBytes"`
	Retention        Duration  `json:"retention"`
}

type Deployment struct {
	Node         string           `json:"node"`
	DataDir      string           `json:"dataDir"`
	Initial      string           `json:"initialConfig"`
	DNS          DNSSettings      `json:"dns"`
	Upstream     UpstreamSettings `json:"upstream"`
	Admin        AdminSettings    `json:"admin"`
	UniFi        UniFiSettings    `json:"unifi"`
	History      HistorySettings  `json:"history"`
	ListDir      string           `json:"listDirectory"`
	ListInterval Duration         `json:"listInterval"`
}

func ReadDeployment(file string) (Deployment, error) {
	d := Deployment{
		DNS: DNSSettings{MaxUDPSize: 1232, Concurrency: 128},
		Upstream: UpstreamSettings{Deadline: Duration(2 * time.Second), CacheEntries: 4096,
			CacheTTL: Duration(300 * time.Second), MaxConnections: 32},
		History:      HistorySettings{Enabled: true, Queue: 4096, MaxBytes: 128 << 20, Retention: Duration(7 * 24 * time.Hour)},
		ListInterval: Duration(24 * time.Hour),
		UniFi:        UniFiSettings{Interval: Duration(60 * time.Second), PageSize: 100},
		Admin:        AdminSettings{SessionTTL: Duration(12 * time.Hour)},
	}
	if err := ReadJSON(file, &d); err != nil {
		return d, err
	}
	base, err := filepath.Abs(filepath.Dir(file))
	if err != nil {
		return d, err
	}
	for _, name := range []*string{&d.DataDir, &d.Initial, &d.ListDir, &d.Admin.KeyFile, &d.Admin.CertFile, &d.Admin.PasswordHash.File,
		&d.Admin.ClientSecret.File, &d.UniFi.CAFile, &d.UniFi.Password.File, &d.UniFi.APIKey.File, &d.Upstream.CAFile, &d.History.AnonymizationKey.File} {
		if *name != "" && !filepath.IsAbs(*name) {
			*name = filepath.Join(base, *name)
		}
	}
	return d, d.Validate()
}

func ReadJSON(file string, v any) error {
	data, err := readBounded(file, 32<<20)
	if err != nil {
		return err
	}
	return DecodeJSON(bytes.NewReader(data), v)
}

func DecodeJSON(r io.Reader, v any) error {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("expected one JSON document")
	}
	return nil
}

func readBounded(file string, limit int64) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds size limit")
	}
	return data, err
}

func (d Deployment) Validate() error {
	if strings.TrimSpace(d.Node) == "" || d.DataDir == "" {
		return errors.New("node and dataDir are required")
	}
	if len(d.DNS.Listen) == 0 || len(d.DNS.Allow) == 0 {
		return errors.New("dns.listen and dns.allow require explicit entries")
	}
	if err := validatePrefixes("dns.allow", d.DNS.Allow); err != nil {
		return err
	}
	if d.DNS.MaxUDPSize < 512 || d.DNS.MaxUDPSize > 4096 || d.DNS.Concurrency < 1 || d.DNS.Concurrency > 4096 {
		return errors.New("dns.maxUDPSize must be 512–4096 and dns.concurrency must be 1–4096")
	}
	bindings := map[string]bool{}
	for _, addr := range d.DNS.Listen {
		host, err := splitListen(addr)
		if err != nil {
			return fmt.Errorf("dns.listen: %w", err)
		}
		if bindings[addr] {
			return errors.New("duplicate DNS listen address")
		}
		bindings[addr] = true
		bootstrap := d.Upstream.BootstrapDNS
		if bootstrap.IsValid() {
			_, port, _ := net.SplitHostPort(addr)
			if port == strconv.Itoa(int(bootstrap.Port())) &&
				(host.Unmap() == bootstrap.Addr().Unmap() ||
					bootstrap.Addr().IsLoopback() && (!host.IsValid() || host.IsUnspecified())) {
				return errors.New("bootstrap DNS cannot use a local Marco listener")
			}
		}
	}
	if d.Upstream.SystemBootstrap && d.Upstream.BootstrapDNS.IsValid() {
		return errors.New("choose either a bootstrap DNS address or independent system bootstrap")
	}
	if b := d.Upstream.BootstrapDNS; b.IsValid() && (b.Port() == 0 || b.Addr().IsUnspecified() || b.Addr().IsMulticast()) {
		return errors.New("bootstrap DNS requires a unicast IP and nonzero port")
	}
	if d.Upstream.MaxConnections < 1 || d.Upstream.MaxConnections > 512 || d.Upstream.CacheEntries < 0 || d.Upstream.CacheEntries > 100000 {
		return errors.New("upstream.maxConnections must be 1–512 and upstream.cacheEntries must be 0–100000")
	}
	if d.Admin.Listen != "" {
		host, err := splitListen(d.Admin.Listen)
		if err != nil {
			return fmt.Errorf("admin.listen: %w", err)
		}
		public, err := url.Parse(d.Admin.PublicURL)
		if err != nil || public.Scheme != "https" || public.Hostname() == "" ||
			public.User != nil || public.Opaque != "" || public.ForceQuery || public.RawQuery != "" || public.Fragment != "" || public.Path != "" && public.Path != "/" {
			return errors.New("admin.publicURL must be an HTTPS origin")
		}
		if d.Admin.KeyFile == "" || d.Admin.CertFile == "" {
			if d.Admin.KeyFile != "" || d.Admin.CertFile != "" || !host.IsLoopback() || len(d.Admin.TrustedProxies) == 0 {
				return errors.New("admin requires a certificate and key or a loopback bind with explicitly trusted HTTPS proxies")
			}
		}
		if err := validatePrefixes("admin.trustedProxies", d.Admin.TrustedProxies); err != nil {
			return err
		}
		if (d.Admin.Username != "") != d.Admin.PasswordHash.Set() {
			return errors.New("local admin requires both username and password hash reference")
		}
		if d.Admin.Issuer == "" {
			if d.Admin.ClientID != "" || d.Admin.ClientSecret.Set() || d.Admin.AdminGroup != "" {
				return errors.New("OIDC settings require an issuer")
			}
		} else if d.Admin.AdminGroup == "" || d.Admin.ClientID == "" || !d.Admin.ClientSecret.Set() {
			return errors.New("OIDC requires client ID, client secret reference and admin group")
		}
		if d.Admin.Username == "" && d.Admin.Issuer == "" {
			return errors.New("configure a local account or an OIDC provider to enable admin")
		}
	}
	if d.UniFi.URL != "" && (d.UniFi.Controller == "" || d.UniFi.Site == "") {
		return errors.New("UniFi requires an explicit controller identity and site")
	}
	if d.History.Enabled && (d.History.Queue < 1 || d.History.Queue > 65536 || d.History.MaxBytes < 1<<20) {
		return errors.New("history requires a queue of 1–65536 and a limit of at least 1 MiB")
	}
	if d.History.Enabled && d.History.Anonymize && !d.History.AnonymizationKey.Set() {
		return errors.New("anonymized history requires an anonymization key reference")
	}
	for _, ref := range []SecretRef{d.Admin.PasswordHash, d.Admin.ClientSecret, d.UniFi.APIKey, d.UniFi.Password, d.History.AnonymizationKey} {
		if ref.Env != "" && ref.File != "" {
			return errors.New("secret reference has both env and file")
		}
	}
	return nil
}

func splitListen(value string) (netip.Addr, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return netip.Addr{}, errors.New("expected IP:port")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil && host != "" {
		return netip.Addr{}, errors.New("listen host must be an IP literal")
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return netip.Addr{}, errors.New("listen port must be 1–65535")
	}
	return ip, nil
}

func validatePrefixes(key string, prefixes []netip.Prefix) error {
	for _, p := range prefixes {
		if !p.IsValid() || p != p.Masked() || p.Bits() == 0 || p.Addr().Is4In6() {
			return fmt.Errorf("%s: expected explicit canonical IPv4 or IPv6 CIDRs", key)
		}
	}
	return nil
}

func (d Deployment) ReadInitial() (Desired, error) {
	c := Defaults()
	if d.Initial == "" {
		return c, nil
	}
	// A portable settings file owns its groups and subscriptions. A file
	// exported without those maps describes an intentionally empty selection.
	c.Groups, c.Subscriptions = nil, nil
	err := ReadJSON(d.Initial, &c)
	return c, err
}
