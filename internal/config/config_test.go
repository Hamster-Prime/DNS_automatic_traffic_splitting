package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigMigratesLegacyListenValues(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	content := []byte(`listen:
  dns_udp: "127.0.0.1:11153"
  dns_tcp: "11153"
  doh: "8443"
`)

	if err := os.WriteFile(configPath, content, 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if got := cfg.Listen.Address; got != "127.0.0.1" {
		t.Fatalf("Listen.Address = %q, want %q", got, "127.0.0.1")
	}
	if got := cfg.Listen.DNSUDP; got != "11153" {
		t.Fatalf("Listen.DNSUDP = %q, want %q", got, "11153")
	}
	if got := cfg.Listen.DNSTCP; got != "11153" {
		t.Fatalf("Listen.DNSTCP = %q, want %q", got, "11153")
	}
	if got := cfg.Listen.DOH; got != "8443" {
		t.Fatalf("Listen.DOH = %q, want %q", got, "8443")
	}
	if got := cfg.Listen.DNSUDPAddr(); got != "127.0.0.1:11153" {
		t.Fatalf("Listen.DNSUDPAddr() = %q, want %q", got, "127.0.0.1:11153")
	}
	if got := cfg.Listen.DNSTCPAddr(); got != "127.0.0.1:11153" {
		t.Fatalf("Listen.DNSTCPAddr() = %q, want %q", got, "127.0.0.1:11153")
	}
	if got := cfg.Listen.DOHAddr(); got != "127.0.0.1:8443" {
		t.Fatalf("Listen.DOHAddr() = %q, want %q", got, "127.0.0.1:8443")
	}
}

func TestListenAddrUsesDefaultAddress(t *testing.T) {
	t.Parallel()

	listen := ListenConfig{DNSUDP: "53"}
	if got := listen.DNSUDPAddr(); got != "0.0.0.0:53" {
		t.Fatalf("Listen.DNSUDPAddr() = %q, want %q", got, "0.0.0.0:53")
	}
}

func TestSaveConfigWritesListenAddressSeparately(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	cfg := &Config{
		Listen: ListenConfig{
			Address: "127.0.0.1",
			DNSUDP:  "11153",
			DNSTCP:  "11153",
			DOH:     "8443",
			DoHPath: "/dns-query",
		},
		Hosts: make(map[string]string),
		Rules: make(map[string]string),
	}

	if err := cfg.Save(configPath); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	text := string(data)
	if !strings.Contains(text, "address: 127.0.0.1") && !strings.Contains(text, "address: \"127.0.0.1\"") {
		t.Fatalf("saved config missing listen address:\n%s", text)
	}
	if strings.Contains(text, "127.0.0.1:11153") {
		t.Fatalf("saved config should not contain merged listen address/port:\n%s", text)
	}

	reloaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() after Save() error = %v", err)
	}
	if got := reloaded.Listen.Address; got != "127.0.0.1" {
		t.Fatalf("reloaded Listen.Address = %q, want %q", got, "127.0.0.1")
	}
	if got := reloaded.Listen.DNSUDP; got != "11153" {
		t.Fatalf("reloaded Listen.DNSUDP = %q, want %q", got, "11153")
	}
}

func TestLoadConfigRespectsExplicitQueryLogDisable(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	content := []byte(`query_log:
  enabled: false
  max_history: 123
`)

	if err := os.WriteFile(configPath, content, 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if cfg.QueryLog.Enabled {
		t.Fatalf("expected explicit query_log.enabled=false to be preserved")
	}
	if cfg.QueryLog.MaxHistory != 123 {
		t.Fatalf("expected query_log.max_history to be loaded, got %d", cfg.QueryLog.MaxHistory)
	}
}

func TestLoadConfigDefaultsQueryLogWhenFieldMissing(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	content := []byte(`listen:
  dns_udp: "53"
`)

	if err := os.WriteFile(configPath, content, 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if !cfg.QueryLog.Enabled {
		t.Fatalf("expected query_log.enabled to default to true when omitted")
	}
	if cfg.QueryLog.MaxHistory != 5000 {
		t.Fatalf("expected query_log.max_history default to 5000, got %d", cfg.QueryLog.MaxHistory)
	}
}
