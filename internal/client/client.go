package client

import (
	"context"
	"fmt"
	"net"

	"doh-autoproxy/internal/config"
	"doh-autoproxy/internal/resolver"

	"github.com/miekg/dns"
)

type DNSClient interface {
	Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

type lifecycleDNSClient interface {
	Close() error
}

func NewDNSClient(cfg config.UpstreamServer, bootstrapper *resolver.Bootstrapper) (DNSClient, error) {
	switch cfg.Protocol {
	case "udp":
		return NewUDPClient(cfg, bootstrapper), nil
	case "tcp":
		return NewTCPClient(cfg, bootstrapper), nil
	case "dot":
		return NewDoTClient(cfg, bootstrapper), nil
	case "doh":
		return NewDoHClient(cfg, bootstrapper), nil
	case "doq":
		return NewDoQClient(cfg, bootstrapper), nil
	default:
		return nil, fmt.Errorf("不支持的上游协议: %s", cfg.Protocol)
	}
}

func CloseDNSClient(c DNSClient) error {
	if c == nil {
		return nil
	}
	if closer, ok := c.(lifecycleDNSClient); ok {
		return closer.Close()
	}
	return nil
}

func ensureECS(req *dns.Msg, ecsIP string) {
	if ecsIP == "" {
		return
	}

	ip := net.ParseIP(ecsIP)
	if ip == nil {
		return
	}

	opt := req.IsEdns0()
	if opt == nil {
		req.SetEdns0(4096, false)
		opt = req.IsEdns0()
	}

	if opt == nil {
		return
	}

	var newOptions []dns.EDNS0
	for _, o := range opt.Option {
		if o.Option() != dns.EDNS0SUBNET {
			newOptions = append(newOptions, o)
		}
	}

	e := new(dns.EDNS0_SUBNET)
	e.Code = dns.EDNS0SUBNET
	if ipv4 := ip.To4(); ipv4 != nil {
		e.Family = 1
		e.SourceNetmask = 24
		e.Address = ipv4
	} else {
		e.Family = 2
		e.SourceNetmask = 56
		e.Address = ip
	}
	newOptions = append(newOptions, e)
	opt.Option = newOptions
}
