package main

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/contract"
	"github.com/pridkett/marco/internal/dnsserver"
)

func TestServiceCatalogPolicy(t *testing.T) {
	catalog, err := config.LoadServiceCatalog("../../catalog/services.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Entries) != 142 || catalog.Entries["youtube"].Icon == "" {
		t.Fatal("unexpected bundled services or missing icon")
	}
	compile, err := newCompiler(config.Deployment{Catalog: catalog})
	if err != nil {
		t.Fatal(err)
	}
	desired := config.Defaults()
	selected := []string{"youtube", "amazon", "qq", "netflix", "discord", "icloud_private_relay"}
	desired.Default.Services = &selected
	view, err := compile(&config.State{Desired: desired}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer view.Upstream.(*forwarder).Close()
	for _, test := range []struct {
		host    string
		qtype   uint16
		blocked bool
	}{
		{"www.youtube.com.", dns.TypeA, true},
		{"sub.nflxvideo.net.", dns.TypeAAAA, true},
		{"dualstack.apiproxy-example.amazonaws.com.", dns.TypeCNAME, true},
		{"hammerandchisel.ssl.zendesk.com.", dns.TypeA, true},
		{"sub.hammerandchisel.ssl.zendesk.com.", dns.TypeA, false},
		{"s3.amazonaws.com.", dns.TypeA, true},
		{"s3.amazonaws.com.", dns.TypeCNAME, false},
		{"qq.com.", dns.TypeA, true},
		{"www.wx.qq.com.", dns.TypeA, false},
		{"mask.icloud.com.", dns.TypeA, true},
	} {
		_, result := dnsserver.Preview(view, contract.Input{Name: test.host, Type: test.qtype,
			Class: dns.ClassINET, Peer: netip.MustParseAddr("192.0.2.100"), Recursion: true})
		if (result.Reason == "service-block") != test.blocked {
			t.Errorf("%s/%d = %+v, want service block=%t", test.host, test.qtype, result, test.blocked)
		}
	}
}
