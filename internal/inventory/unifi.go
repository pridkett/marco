package inventory

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pridkett/marco/internal/config"
)

const maxPageBytes = 8 << 20
const maxRows = 100_000

type Adapter interface {
	Poll(context.Context) (Snapshot, error)
}

type Settings struct {
	Controller, URL, Site, APIKey, Username, Password, CACertFile, Mode string
	PageSize                                                            int
	DialIP                                                              netip.Addr
}

type adapter struct {
	c        Settings
	origin   *url.URL
	client   *http.Client
	mu       sync.Mutex
	local    bool
	proxy    string
	loggedIn bool
	csrf     string
}

// NewAdapter supports the official Network API by default. Operators can
// select local-account compatibility for firmware without its required fields.
func NewAdapter(c Settings) (Adapter, error) {
	if c.Controller == "" || c.Site == "" || strings.ContainsAny(c.Controller, "/\x00") ||
		strings.TrimSpace(c.Controller) != c.Controller || !siteSegment(c.Site) {
		return nil, errors.New("UniFi requires a controller ID and a site ID or name")
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" ||
		u.User != nil || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return nil, errors.New("UniFi URL must be an HTTPS origin")
	}
	if err := config.ValidateUniFiDialIP(c.DialIP); err != nil {
		return nil, err
	}
	if c.PageSize == 0 {
		c.PageSize = 100
	}
	if c.PageSize < 1 || c.PageSize > 1000 {
		return nil, errors.New("UniFi page size must be between 1 and 1000")
	}
	a := &adapter{c: c, origin: u}
	switch c.Mode {
	case "", "api-key":
		a.proxy = "/proxy/network"
	case "api-key-standalone":
	case "local-account":
		a.local, a.proxy = true, "/proxy/network"
	case "local-account-standalone":
		a.local = true
	default:
		return nil, errors.New("unknown UniFi adapter mode")
	}
	if a.local && (c.Username == "" || c.Password == "") || !a.local && c.APIKey == "" {
		return nil, errors.New("UniFi credentials are required for the selected mode")
	}
	var roots *x509.CertPool
	if c.CACertFile != "" {
		cert, err := os.ReadFile(c.CACertFile)
		if err != nil {
			return nil, errors.New("could not read the UniFi CA file")
		}
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, errors.New("could not load the system certificate store")
		}
		if !roots.AppendCertsFromPEM(cert) {
			return nil, errors.New("UniFi CA file contains no valid certificates")
		}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	dial := dialer.DialContext
	if c.DialIP.IsValid() {
		// Override the socket destination while the HTTPS transport retains
		// the URL hostname for HTTP routing, SNI, and certificate verification.
		dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(c.DialIP.Unmap().String(), port))
		}
	}
	transport := &http.Transport{
		DialContext:       dial,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		ForceAttemptHTTP2: true, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 2,
		IdleConnTimeout: 90 * time.Second, ResponseHeaderTimeout: 8 * time.Second,
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create UniFi session cookie store: %w", err)
	}
	a.client = &http.Client{
		Transport: transport, Jar: jar, Timeout: 12 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return a, nil
}

func siteSegment(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.", c) {
			return false
		}
	}
	return true
}

type HTTPError struct {
	Status     int
	RetryAfter time.Duration
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("UniFi returned HTTP %d", e.Status)
}

func retryAfter(value string, now time.Time) time.Duration {
	if seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil && seconds >= 0 {
		return time.Duration(min(seconds, int64((1<<63-1)/time.Second))) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		return max(0, when.Sub(now))
	}
	return 0
}

func (a *adapter) request(ctx context.Context, method, path, query string, payload []byte, out any) (http.Header, error) {
	u := *a.origin
	u.Path, u.RawQuery = path, query
	r, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, errors.New("could not construct UniFi request")
	}
	r.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
	}
	if !a.local {
		r.Header.Set("X-API-Key", a.c.APIKey)
	} else if a.csrf != "" {
		r.Header.Set("X-CSRF-Token", a.csrf)
	}
	resp, err := a.client.Do(r)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var unknown x509.UnknownAuthorityError
		var wrongHost x509.HostnameError
		var certificate x509.CertificateInvalidError
		if errors.As(err, &unknown) || errors.As(err, &wrongHost) || errors.As(err, &certificate) {
			return nil, errors.New("UniFi TLS certificate verification failed")
		}
		return nil, errors.New("UniFi request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, &HTTPError{resp.StatusCode, retryAfter(resp.Header.Get("Retry-After"), time.Now())}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPageBytes+1))
	if err != nil {
		return nil, errors.New("could not read UniFi response")
	}
	if len(body) > maxPageBytes {
		return nil, errors.New("UniFi response exceeds the page size limit")
	}
	if out != nil && json.Unmarshal(body, out) != nil {
		return nil, errors.New("malformed UniFi JSON response")
	}
	return resp.Header, nil
}

func (a *adapter) Poll(ctx context.Context) (Snapshot, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var obs []Observation
	var err error
	if a.local {
		obs, err = a.localPoll(ctx)
		var httpErr *HTTPError
		if a.loggedIn && errors.As(err, &httpErr) &&
			(httpErr.Status == http.StatusUnauthorized || httpErr.Status == http.StatusForbidden) {
			a.loggedIn, a.csrf = false, ""
			obs, err = a.localPoll(ctx)
		}
	} else {
		obs, err = a.officialPoll(ctx)
	}
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{
		Controller: a.c.Controller, Site: a.c.Site, ObservedAt: time.Now().UTC(),
		Complete: true, Observations: obs,
	}, nil
}

func (a *adapter) CloseIdleConnections() {
	a.client.CloseIdleConnections()
}

type apiRow struct {
	ID        string          `json:"id"`
	MAC       string          `json:"macAddress"`
	IP        string          `json:"ipAddress"`
	Name      string          `json:"name"`
	Hostname  string          `json:"hostname"`
	Network   string          `json:"networkName"`
	NetworkID string          `json:"networkId"`
	VLAN      json.RawMessage `json:"vlan"`
	State     string          `json:"state"`
	LastSeen  json.RawMessage `json:"lastSeen"`
}

type page struct {
	Data   []apiRow `json:"data"`
	Offset *int     `json:"offset"`
	Limit  *int     `json:"limit"`
	Count  *int     `json:"count"`
	Total  *int     `json:"totalCount"`
}

func (a *adapter) pages(ctx context.Context, path string) ([]apiRow, error) {
	var rows []apiRow
	total := -1
	ids := make(map[string]bool)
	for offset := 0; total < 0 || offset < total; {
		query := url.Values{"offset": {strconv.Itoa(offset)}, "limit": {strconv.Itoa(a.c.PageSize)}}
		var p page
		if _, err := a.request(ctx, http.MethodGet, path, query.Encode(), nil, &p); err != nil {
			return nil, err
		}
		if p.Offset == nil || p.Total == nil || p.Count == nil || p.Limit == nil || p.Data == nil ||
			*p.Offset != offset || *p.Total < 0 || *p.Total > maxRows || (total >= 0 && total != *p.Total) ||
			*p.Count != len(p.Data) || len(p.Data) > *p.Limit || offset+len(p.Data) > *p.Total ||
			(len(p.Data) == 0 && offset < *p.Total) {
			return nil, errors.New("incomplete or inconsistent UniFi pagination")
		}
		for _, row := range p.Data {
			if row.ID == "" || ids[row.ID] {
				return nil, errors.New("missing or duplicated row ID in UniFi pagination")
			}
			ids[row.ID] = true
		}
		total = *p.Total
		rows = append(rows, p.Data...)
		offset += len(p.Data)
	}
	return rows, nil
}

func (a *adapter) officialPoll(ctx context.Context) ([]Observation, error) {
	base := a.proxy + "/integration/v1/sites/" + a.c.Site
	clients, err := a.pages(ctx, base+"/clients")
	if err != nil {
		return nil, fmt.Errorf("UniFi connected clients: %w", err)
	}
	devices, err := a.pages(ctx, base+"/devices")
	if err != nil {
		return nil, fmt.Errorf("UniFi adopted devices: %w", err)
	}
	out := make([]Observation, 0, len(clients)+len(devices))
	for i, row := range append(clients, devices...) {
		kind, present := "client", true
		if i >= len(clients) {
			kind, present = "device", row.State == "ONLINE"
		}
		obs, err := normalizeRow(kind+":"+row.ID, row.MAC, row.IP, row.Name, row.Hostname,
			networkLabel(row.Network, row.NetworkID, row.VLAN), present, row.LastSeen)
		if err != nil {
			return nil, err
		}
		out = append(out, obs)
	}
	return out, nil
}

type localRow struct {
	ID                  string          `json:"_id"`
	MAC                 string          `json:"mac"`
	IP                  string          `json:"ip"`
	Name                string          `json:"name"`
	Hostname            string          `json:"hostname"`
	Network             string          `json:"network"`
	NetworkID           string          `json:"network_id"`
	VLAN                json.RawMessage `json:"vlan"`
	State               json.RawMessage `json:"state"`
	LastSeen            json.RawMessage `json:"last_seen"`
	Fingerprint         json.RawMessage `json:"dev_id"`
	FingerprintOverride json.RawMessage `json:"dev_id_override"`
}

func (r localRow) fingerprintID() uint32 {
	for _, field := range []json.RawMessage{r.FingerprintOverride, r.Fingerprint} {
		id, err := strconv.ParseUint(strings.Trim(string(field), `"`), 10, 32)
		if err == nil && id > 0 {
			return uint32(id)
		}
	}
	return 0
}

func (a *adapter) login(ctx context.Context) error {
	path := "/api/login"
	if a.proxy != "" {
		path = "/api/auth/login"
	}
	payload, err := json.Marshal(map[string]string{"username": a.c.Username, "password": a.c.Password})
	if err != nil {
		return errors.New("could not encode UniFi sign-in")
	}
	headers, err := a.request(ctx, http.MethodPost, path, "", payload, nil)
	if err != nil {
		return err
	}
	a.csrf = headers.Get("X-CSRF-Token")
	a.loggedIn = true
	return nil
}

func (a *adapter) localPoll(ctx context.Context) ([]Observation, error) {
	if !a.loggedIn {
		if err := a.login(ctx); err != nil {
			return nil, fmt.Errorf("UniFi local sign-in: %w", err)
		}
	}
	base := a.proxy + "/api/s/" + a.c.Site + "/stat/"
	var out []Observation
	for _, endpoint := range []string{"sta", "device"} {
		var response struct {
			Meta struct {
				RC string `json:"rc"`
			} `json:"meta"`
			Data []localRow `json:"data"`
		}
		if _, err := a.request(ctx, http.MethodGet, base+endpoint, "", nil, &response); err != nil {
			return nil, fmt.Errorf("UniFi compatibility snapshot: %w", err)
		}
		if response.Meta.RC != "ok" || response.Data == nil || len(response.Data) > maxRows {
			return nil, errors.New("incomplete UniFi compatibility snapshot")
		}
		for _, row := range response.Data {
			current := endpoint == "sta"
			state := strings.Trim(string(row.State), `"`)
			present := current || state == "1" || state == "ONLINE"
			id := ""
			if row.ID != "" {
				id = endpoint + ":" + row.ID
			}
			obs, err := normalizeRow(id, row.MAC, row.IP, row.Name, row.Hostname,
				networkLabel(row.Network, row.NetworkID, row.VLAN), present, row.LastSeen)
			if err != nil {
				return nil, err
			}
			obs.UniFiFingerprint = row.fingerprintID()
			out = append(out, obs)
		}
	}
	return out, nil
}

func networkLabel(name, id string, vlan json.RawMessage) string {
	if name != "" {
		return name
	}
	if value, err := strconv.ParseUint(strings.Trim(string(vlan), `"`), 10, 12); err == nil {
		return fmt.Sprintf("VLAN %d", value)
	}
	return id
}

func parseSeen(raw json.RawMessage) (seen time.Time, missing bool) {
	value := strings.Trim(string(raw), `"`)
	if value == "" || value == "null" || value == "0" {
		return time.Time{}, true
	}
	if when, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return when.UTC(), false
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 {
		return time.Unix(seconds, 0).UTC(), false
	}
	return time.Time{}, false
}

func normalizeRow(id, mac, ip, name, hostname, network string, present bool, rawSeen json.RawMessage) (Observation, error) {
	mac, err := normalizeMAC(mac)
	if err != nil {
		return Observation{}, err
	}
	if mac == "" && id == "" {
		return Observation{}, errors.New("UniFi row lacks a stable device identity")
	}
	seen, missing := parseSeen(rawSeen)
	row := Observation{
		SourceID: id, MAC: mac, Reported: name, Hostname: hostname, Network: network,
		LastSeen: seen, Present: present, UseObservationTime: missing && present,
	}
	if strings.TrimSpace(ip) != "" {
		addr, err := netip.ParseAddr(strings.TrimSpace(ip))
		if err != nil {
			return Observation{}, errors.New("invalid IP address in UniFi snapshot")
		}
		if validAddress(addr) && !addr.IsLoopback() {
			addr = addr.Unmap()
			row.Addresses = []netip.Addr{addr}
			// These surfaces report a single primary address. They can confirm
			// replacement of a primary IPv4 address without claiming visibility
			// of all secondary IPv4 or IPv6 addresses.
			row.CompleteIPv4 = addr.Is4()
		}
	}
	return row, nil
}
