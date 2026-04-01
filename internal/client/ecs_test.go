package client

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestExtractECSReturnsNormalizedCIDR(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(4096, false)

	opt := req.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 24,
		Address:       net.ParseIP("203.0.113.42").To4(),
	})

	if got := ExtractECS(req); got != "203.0.113.0/24" {
		t.Fatalf("expected normalized ECS, got %q", got)
	}
}

func TestExtractECSReturnsEmptyWhenMissing(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	if got := ExtractECS(req); got != "" {
		t.Fatalf("expected empty ECS, got %q", got)
	}
}
