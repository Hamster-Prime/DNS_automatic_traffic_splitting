package router

import (
	"context"
	"net"
	"regexp"
	"testing"

	"doh-autoproxy/internal/client"
	"doh-autoproxy/internal/config"

	"github.com/miekg/dns"
)

type fakeDNSClient struct {
	resp *dns.Msg
	err  error
}

func (f fakeDNSClient) Resolve(context.Context, *dns.Msg) (*dns.Msg, error) {
	if f.resp == nil {
		return nil, f.err
	}
	return f.resp.Copy(), f.err
}

func TestMatchNamesStripsLeadingUnderscoreLabels(t *testing.T) {
	tests := []struct {
		name     string
		qName    string
		expected []string
	}{
		{
			name:  "https service binding with port",
			qName: "_8084._https.xxjsbigdata.scbdc.edu.cn.",
			expected: []string{
				"_8084._https.xxjsbigdata.scbdc.edu.cn",
				"_https.xxjsbigdata.scbdc.edu.cn",
				"xxjsbigdata.scbdc.edu.cn",
			},
		},
		{
			name:  "acme challenge",
			qName: "_acme-challenge.example.com",
			expected: []string{
				"_acme-challenge.example.com",
				"example.com",
			},
		},
		{
			name:  "regular hostname",
			qName: "www.example.com.",
			expected: []string{
				"www.example.com",
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := matchNames(tc.qName)
			if len(got) != len(tc.expected) {
				t.Fatalf("expected %d names, got %d: %v", len(tc.expected), len(got), got)
			}
			for i := range tc.expected {
				if got[i] != tc.expected[i] {
					t.Fatalf("expected names %v, got %v", tc.expected, got)
				}
			}
		})
	}
}

func TestRouteInternalMatchesRuleForHTTPSServiceName(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("_8084._https.xxjsbigdata.scbdc.edu.cn.", dns.TypeHTTPS)

	overseasResp := new(dns.Msg)
	overseasResp.SetReply(req)

	r := &Router{
		config: &config.Config{
			Rules: map[string]string{
				"xxjsbigdata.scbdc.edu.cn": "overseas",
			},
			Hosts: map[string]string{},
		},
		overseasClients: []client.DNSClient{
			fakeDNSClient{resp: overseasResp},
		},
	}

	resp, upstream, err := r.routeInternal(context.Background(), req)
	if err != nil {
		t.Fatalf("routeInternal returned error: %v", err)
	}
	if upstream != "Rule(Overseas)" {
		t.Fatalf("expected Rule(Overseas), got %q", upstream)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected successful response, got %#v", resp)
	}
}

func TestRouteInternalMatchesRegexForServiceNameAlias(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("_xmpp-client._tcp.example.com.", dns.TypeSRV)

	cnResp := new(dns.Msg)
	cnResp.SetReply(req)

	r := &Router{
		config: &config.Config{
			Rules: map[string]string{},
			Hosts: map[string]string{},
		},
		regexRules: []RegexRule{
			{
				Pattern: regexp.MustCompile(`^example\.com$`),
				Target:  "cn",
			},
		},
		cnClients: []client.DNSClient{
			fakeDNSClient{resp: cnResp},
		},
	}

	resp, upstream, err := r.routeInternal(context.Background(), req)
	if err != nil {
		t.Fatalf("routeInternal returned error: %v", err)
	}
	if upstream != "Rule(Regex/CN)" {
		t.Fatalf("expected Rule(Regex/CN), got %q", upstream)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected successful response, got %#v", resp)
	}
}

func TestHostOverrideOnlyAppliesToAddressQueries(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeHTTPS)

	resp, ok := hostOverrideResponse(req, net.ParseIP("1.2.3.4"))
	if ok {
		t.Fatalf("expected HTTPS query not to be answered by hosts override, got %#v", resp)
	}
}
