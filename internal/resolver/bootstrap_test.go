package resolver

import "testing"

func TestParseBootstrapServerDefaultsToUDP(t *testing.T) {
	server := parseBootstrapServer("8.8.8.8")

	if server.network != "udp" {
		t.Fatalf("expected udp network, got %q", server.network)
	}
	if server.address != "8.8.8.8:53" {
		t.Fatalf("expected default port to be appended, got %q", server.address)
	}
}

func TestParseBootstrapServerSupportsTCPPrefix(t *testing.T) {
	server := parseBootstrapServer("tcp://2001:4860:4860::8888")

	if server.network != "tcp" {
		t.Fatalf("expected tcp network, got %q", server.network)
	}
	if server.address != "[2001:4860:4860::8888]:53" {
		t.Fatalf("expected IPv6 address with default port, got %q", server.address)
	}
}

func TestNewBootstrapperSkipsEmptyEntries(t *testing.T) {
	bootstrapper := NewBootstrapper([]string{"", "  ", "1.1.1.1:53"})

	if len(bootstrapper.servers) != 1 {
		t.Fatalf("expected 1 bootstrap server, got %d", len(bootstrapper.servers))
	}
}
