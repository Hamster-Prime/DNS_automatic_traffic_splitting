package resolver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type cacheEntry struct {
	ip     string
	expiry time.Time
}

type bootstrapServer struct {
	network string
	address string
}

func (s bootstrapServer) String() string {
	if s.network == "" || s.network == "udp" {
		return s.address
	}
	return s.network + "://" + s.address
}

type Bootstrapper struct {
	servers  []bootstrapServer
	counter  uint64
	cache    sync.Map
	cacheTTL time.Duration
}

func NewBootstrapper(servers []string) *Bootstrapper {
	normalized := make([]bootstrapServer, 0, len(servers))
	for _, s := range servers {
		parsed := parseBootstrapServer(s)
		if parsed.address == "" {
			continue
		}
		normalized = append(normalized, parsed)
	}
	return &Bootstrapper{
		servers:  normalized,
		cacheTTL: 5 * time.Minute,
	}
}

func parseBootstrapServer(server string) bootstrapServer {
	raw := strings.TrimSpace(server)
	if raw == "" {
		return bootstrapServer{}
	}

	network := "udp"
	if idx := strings.Index(raw, "://"); idx >= 0 {
		switch strings.ToLower(raw[:idx]) {
		case "tcp":
			network = "tcp"
		case "udp":
			network = "udp"
		}
		raw = strings.TrimSpace(raw[idx+3:])
	}

	if raw == "" {
		return bootstrapServer{}
	}

	if _, _, err := net.SplitHostPort(raw); err != nil {
		raw = net.JoinHostPort(raw, "53")
	}

	return bootstrapServer{
		network: network,
		address: raw,
	}
}

func (b *Bootstrapper) LookupIP(ctx context.Context, host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}

	// 查缓存
	if entry, ok := b.cache.Load(host); ok {
		ce := entry.(*cacheEntry)
		if time.Now().Before(ce.expiry) {
			return ce.ip, nil
		}
		b.cache.Delete(host)
	}

	ip, err := b.lookupWithRetry(ctx, host)
	if err != nil {
		return "", err
	}

	// 写入缓存
	b.cache.Store(host, &cacheEntry{
		ip:     ip,
		expiry: time.Now().Add(b.cacheTTL),
	})

	return ip, nil
}

func (b *Bootstrapper) lookupWithRetry(ctx context.Context, host string) (string, error) {
	if len(b.servers) == 0 {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return "", err
		}
		if len(ips) == 0 {
			return "", fmt.Errorf("no IP found for %s", host)
		}
		return ips[0].String(), nil
	}

	// 从当前轮询位置开始，依次尝试所有 bootstrap 服务器
	startIdx := atomic.AddUint64(&b.counter, 1)
	var lastErr error

	for i := 0; i < len(b.servers); i++ {
		server := b.servers[(startIdx+uint64(i))%uint64(len(b.servers))]

		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: 3 * time.Second,
				}
				return d.DialContext(ctx, server.network, server.address)
			},
		}

		resolveCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		ips, err := r.LookupIPAddr(resolveCtx, host)
		cancel()

		if err != nil {
			lastErr = fmt.Errorf("bootstrap %s failed: %w", server, err)
			continue
		}
		if len(ips) == 0 {
			lastErr = fmt.Errorf("no IP found for %s via bootstrap %s", host, server)
			continue
		}

		return ips[0].String(), nil
	}

	return "", fmt.Errorf("all bootstrap servers failed for %s: %w", host, lastErr)
}
