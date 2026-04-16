package client

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"doh-autoproxy/internal/config"
	"doh-autoproxy/internal/resolver"

	"github.com/miekg/dns"
)

type TCPClient struct {
	cfg          config.UpstreamServer
	bootstrapper *resolver.Bootstrapper
	pool         chan *dns.Conn
	poolInit     sync.Once
	closed       atomic.Bool
}

func NewTCPClient(cfg config.UpstreamServer, b *resolver.Bootstrapper) *TCPClient {
	return &TCPClient{
		cfg:          cfg,
		bootstrapper: b,
	}
}

func (c *TCPClient) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	ensureECS(req, c.cfg.ECSIP)

	if c.cfg.EnablePipeline {
		return c.resolvePipeline(ctx, req)
	}
	return c.resolveOneshot(ctx, req)
}

func (c *TCPClient) resolveOneshot(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	addr, err := c.resolveAddr(ctx)
	if err != nil {
		return nil, err
	}

	cli := &dns.Client{
		Net:     "tcp",
		Timeout: 5 * time.Second,
	}

	resp, _, err := cli.ExchangeContext(ctx, req, addr)
	if err != nil {
		return nil, fmt.Errorf("TCP查询失败: %w", err)
	}
	return resp, nil
}

func (c *TCPClient) initPool() {
	c.poolInit.Do(func() {
		c.pool = make(chan *dns.Conn, 10)
		for i := 0; i < 10; i++ {
			c.pool <- nil
		}
	})
}

func (c *TCPClient) resolvePipeline(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	c.initPool()

	var conn *dns.Conn
	select {
	case conn = <-c.pool:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	defer func() {
		if conn == nil {
			return
		}
		if c.closed.Load() {
			conn.Close()
			return
		}
		c.pool <- conn
	}()

	var err error
	if conn == nil {
		conn, err = c.dialConn(ctx)
		if err != nil {
			return nil, err
		}
	}

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := conn.WriteMsg(req); err != nil {
		conn.Close()
		conn = nil
		conn, err = c.dialConn(ctx)
		if err != nil {
			return nil, fmt.Errorf("重连失败: %w", err)
		}
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := conn.WriteMsg(req); err != nil {
			conn.Close()
			conn = nil
			return nil, fmt.Errorf("写入失败: %w", err)
		}
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := conn.ReadMsg()
	if err != nil {
		conn.Close()
		conn = nil
		return nil, fmt.Errorf("读取失败: %w", err)
	}

	if resp.Id != req.Id {
		conn.Close()
		conn = nil
		return nil, fmt.Errorf("ID mismatch")
	}

	return resp, nil
}

func (c *TCPClient) dialConn(ctx context.Context) (*dns.Conn, error) {
	addr, err := c.resolveAddr(ctx)
	if err != nil {
		return nil, err
	}

	cli := &dns.Client{Net: "tcp", Timeout: 5 * time.Second}
	conn, err := cli.Dial(addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *TCPClient) resolveAddr(ctx context.Context) (string, error) {
	rawAddr := c.cfg.Address
	host, port, err := net.SplitHostPort(rawAddr)
	if err != nil {
		rawAddr = net.JoinHostPort(rawAddr, "53")
		host, port, err = net.SplitHostPort(rawAddr)
		if err != nil {
			return "", fmt.Errorf("invalid address %s: %w", c.cfg.Address, err)
		}
	}

	ip, err := c.bootstrapper.LookupIP(ctx, host)
	if err != nil {
		return "", fmt.Errorf("bootstrap failed: %w", err)
	}
	return net.JoinHostPort(ip, port), nil
}

func (c *TCPClient) Close() error {
	c.closed.Store(true)
	if c.pool == nil {
		return nil
	}

	var firstErr error
	for {
		select {
		case conn := <-c.pool:
			if conn == nil {
				continue
			}
			if err := conn.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		default:
			return firstErr
		}
	}
}
