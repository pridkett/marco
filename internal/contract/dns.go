// Package contract contains the query and integration interfaces shared by the DNS path.
package contract

import (
	"context"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/config"
)

type Input struct {
	Name             string
	Type             uint16
	Class            uint16
	Peer             netip.Addr
	Time             time.Time
	Recursion        bool
	EDNS             bool
	DNSSEC           bool
	CheckingDisabled bool
	BlockingPaused   bool
}

// BlockingPause is a temporary instance-wide bypass for domain filtering.
// A paused state with no deadline lasts until an administrator resumes it.
type BlockingPause struct {
	Paused bool      `json:"paused"`
	Until  time.Time `json:"until,omitzero"`
}

func (p BlockingPause) At(now time.Time) BlockingPause {
	if p.Paused && (p.Until.IsZero() || now.Before(p.Until)) {
		return p
	}
	return BlockingPause{}
}

type Result struct {
	RCode  int
	Origin string
	Reason string
	Rule   string
	Cache  string
}

type Event struct {
	Input
	Result
	Node    string
	Latency time.Duration
}

type Selection struct {
	Device     string
	Group      string
	Confidence string
	Precedence string
	Assignment string
	Seen       time.Time
	Policy     config.Policy
}

type Decision struct {
	Blocked bool
	Allowed bool
	Reason  string
	Rule    string
}

type Policies interface {
	Select(netip.Addr, time.Time) Selection
	Manual(Selection, string) Decision
	External(Selection, string, uint16, time.Time) Decision
}

type LocalResult struct {
	Found         bool
	Code          int
	Answer        []dns.RR
	Authority     []dns.RR
	PublicTarget  string
	Suppressed    bool
	Authoritative bool
}

type Local interface {
	Lookup(name string, qtype uint16) LocalResult
}

type Upstream interface {
	Exchange(context.Context, string, *dns.Msg) (*dns.Msg, bool, error)
}

type View struct {
	Revision   uint64
	Policies   Policies
	Local      Local
	Upstream   Upstream
	Forwarding map[string]string // Canonical DNS suffixes mapped to upstream pools.
}

type Update func(ctx context.Context, base uint64, change func(*config.State) error) (uint64, error)
