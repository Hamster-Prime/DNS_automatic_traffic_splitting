package client

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type StatsClient struct {
	Client   DNSClient
	Address  string
	Protocol string
	Group    string

	mu            sync.RWMutex
	TotalQueries  int64
	TotalErrors   int64
	TotalCanceled int64
	TotalDuration int64
}

func NewStatsClient(c DNSClient, address, protocol, group string) *StatsClient {
	return &StatsClient{
		Client:   c,
		Address:  address,
		Protocol: protocol,
		Group:    group,
	}
}

func (s *StatsClient) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	start := time.Now()
	resp, err := s.Client.Resolve(ctx, req)
	duration := time.Since(start).Microseconds()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.TotalQueries++
	s.TotalDuration += duration
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			s.TotalCanceled++
		} else {
			s.TotalErrors++
		}
	} else {
	}

	return resp, err
}

func (s *StatsClient) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	avg := int64(0)
	if s.TotalQueries > 0 {
		avg = s.TotalDuration / s.TotalQueries / 1000
	}

	return map[string]interface{}{
		"address":         s.Address,
		"protocol":        s.Protocol,
		"group":           s.Group,
		"total_queries":   s.TotalQueries,
		"total_errors":    s.TotalErrors,
		"total_canceled":  s.TotalCanceled,
		"avg_duration_ms": avg,
	}
}

func (s *StatsClient) Close() error {
	return CloseDNSClient(s.Client)
}
