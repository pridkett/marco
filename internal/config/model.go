// Package config defines the portable desired configuration and durable DNS state.
package config

import (
	"net/netip"
	"time"
)

const Version = 1

type Mode string

const (
	Filtered   Mode = "filtered"
	Unfiltered Mode = "unfiltered"
	LocalOnly  Mode = "local-only"
	DenyAll    Mode = "deny-all"
)

type Rule struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name"`
	Suffix bool   `json:"suffix,omitempty"`
	Allow  bool   `json:"allow,omitempty"`
}

type Policy struct {
	Mode          Mode      `json:"mode,omitempty"`
	Services      *[]string `json:"services,omitempty"`
	Subscriptions *[]string `json:"subscriptions,omitempty"`
	Pool          string    `json:"pool,omitempty"`
	Rules         []Rule    `json:"rules,omitempty"`
}

type Assignment struct {
	Prefix netip.Prefix `json:"prefix"`
	Device string       `json:"device,omitempty"`
	Group  string       `json:"group,omitempty"`
	Policy Policy       `json:"policy,omitempty"`
}

type DeviceSettings struct {
	Name      string       `json:"name,omitempty"`
	Group     string       `json:"group,omitempty"`
	Policy    Policy       `json:"policy,omitempty"`
	Unpublish bool         `json:"unpublish,omitempty"`
	Aliases   []string     `json:"aliases,omitempty"`
	Pinned    []netip.Addr `json:"pinned,omitempty"`
	Links     []string     `json:"links,omitempty"`
}

type Zone struct {
	Name    string `json:"name"`
	Private bool   `json:"private,omitempty"`
	Publish bool   `json:"publish,omitempty"`
}

type Record struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	TTL    uint32 `json:"ttl,omitempty"`
	Public bool   `json:"public,omitempty"`
}

type Suppression struct {
	Name    string     `json:"name,omitempty"`
	Address netip.Addr `json:"address,omitempty"`
}

type Endpoint struct {
	Transport  string       `json:"transport"`
	Address    string       `json:"address,omitempty"`
	Port       uint16       `json:"port,omitempty"`
	ServerName string       `json:"serverName,omitempty"`
	Bootstrap  []netip.Addr `json:"bootstrap,omitempty"`
	URL        string       `json:"url,omitempty"`
}

type Service struct {
	Version string `json:"version"`
	Domains []Rule `json:"domains"`
}

const AdGuardFormat = "adguard"

type Subscription struct {
	Name       string `json:"name,omitempty"`
	Format     string `json:"format,omitempty"`
	URL        string `json:"url,omitempty"`
	File       string `json:"file,omitempty"`
	Enabled    bool   `json:"enabled"`
	AllowEmpty bool   `json:"allowEmpty,omitempty"`
	Allowlist  bool   `json:"allowlist,omitempty"`
}

type Desired struct {
	Version       int                       `json:"version"`
	Default       Policy                    `json:"default"`
	Groups        map[string]Policy         `json:"groups,omitempty"`
	Assignments   []Assignment              `json:"assignments,omitempty"`
	Devices       map[string]DeviceSettings `json:"devices,omitempty"`
	Zones         []Zone                    `json:"zones,omitempty"`
	Reverse       []netip.Prefix            `json:"reverse,omitempty"`
	Records       []Record                  `json:"records,omitempty"`
	Suppressions  []Suppression             `json:"suppressions,omitempty"`
	DynamicTTL    uint32                    `json:"dynamicTTL,omitempty"`
	StaticTTL     uint32                    `json:"staticTTL,omitempty"`
	MultiplePTRs  bool                      `json:"multiplePTRs,omitempty"`
	AutoRename    bool                      `json:"autoRename,omitempty"`
	Pools         map[string][]Endpoint     `json:"pools,omitempty"`
	Services      map[string]Service        `json:"services,omitempty"`
	Subscriptions map[string]Subscription   `json:"subscriptions,omitempty"`
}

type Address struct {
	IP         netip.Addr `json:"ip"`
	LastSeen   time.Time  `json:"lastSeen,omitempty"`
	Provenance string     `json:"provenance,omitempty"`
	Active     bool       `json:"active,omitempty"`
	Publish    bool       `json:"publish,omitempty"`
	Superseded bool       `json:"superseded,omitempty"`
	Reassigned bool       `json:"reassigned,omitempty"`
	Conflicted bool       `json:"conflicted,omitempty"`
}

type Device struct {
	ID          string    `json:"id"`
	Controller  string    `json:"controller,omitempty"`
	Site        string    `json:"site,omitempty"`
	MAC         string    `json:"mac,omitempty"`
	SourceID    string    `json:"sourceID,omitempty"`
	Canonical   string    `json:"canonical,omitempty"`
	Reported    string    `json:"reported,omitempty"`
	Hostname    string    `json:"hostname,omitempty"`
	Network     string    `json:"network,omitempty"`
	FirstSeen   time.Time `json:"firstSeen,omitempty"`
	LastSeen    time.Time `json:"lastSeen,omitempty"`
	LastPoll    time.Time `json:"lastPoll,omitempty"`
	Connected   bool      `json:"connected,omitempty"`
	Legacy      bool      `json:"legacy,omitempty"`
	LegacyOwner string    `json:"legacyOwner,omitempty"`
	Addresses   []Address `json:"addresses,omitempty"`
}

type Artifact struct {
	Source       Subscription `json:"source"`
	Body         []byte       `json:"body"`
	Digest       string       `json:"digest"`
	ETag         string       `json:"etag,omitempty"`
	LastModified string       `json:"lastModified,omitempty"`
	FetchedAt    time.Time    `json:"fetchedAt"`
	RuleCount    int          `json:"ruleCount"`
}

type State struct {
	Imports   map[string]time.Time `json:"imports,omitempty"`
	Revision  uint64               `json:"revision"`
	Desired   Desired              `json:"desired"`
	Devices   map[string]Device    `json:"devices,omitempty"`
	SitePolls map[string]time.Time `json:"sitePolls,omitempty"`
	Artifacts map[string]Artifact  `json:"artifacts,omitempty"`
}

func Defaults() Desired {
	return Desired{Version: Version, Default: Policy{Mode: Filtered}, DynamicTTL: 60, StaticTTL: 300}
}
