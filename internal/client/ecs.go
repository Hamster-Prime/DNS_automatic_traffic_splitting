package client

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

func ExtractECS(req *dns.Msg) string {
	opt := req.IsEdns0()
	if opt == nil {
		return ""
	}

	for _, option := range opt.Option {
		subnet, ok := option.(*dns.EDNS0_SUBNET)
		if !ok {
			continue
		}
		return formatECS(subnet)
	}

	return ""
}

func formatECS(subnet *dns.EDNS0_SUBNET) string {
	if subnet == nil || subnet.Address == nil {
		return ""
	}

	ip := subnet.Address
	bits := 128
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
		bits = 32
	}

	prefix := int(subnet.SourceNetmask)
	if prefix < 0 {
		prefix = 0
	}
	if prefix > bits {
		prefix = bits
	}

	masked := ip.Mask(net.CIDRMask(prefix, bits))
	if masked == nil {
		return ip.String()
	}

	return fmt.Sprintf("%s/%d", masked.String(), prefix)
}
