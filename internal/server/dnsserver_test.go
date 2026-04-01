package server

import (
	"net"
	"testing"

	"doh-autoproxy/internal/config"
	"doh-autoproxy/internal/router"

	"github.com/miekg/dns"
)

type captureResponseWriter struct {
	msg *dns.Msg
}

func (w *captureResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 53}
}

func (w *captureResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (w *captureResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.msg = msg.Copy()
	return nil
}

func (w *captureResponseWriter) Write(buf []byte) (int, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(buf); err != nil {
		return 0, err
	}
	w.msg = msg
	return len(buf), nil
}

func (w *captureResponseWriter) Close() error {
	return nil
}

func (w *captureResponseWriter) TsigStatus() error {
	return nil
}

func (w *captureResponseWriter) TsigTimersOnly(bool) {}

func (w *captureResponseWriter) Hijack() {}

func TestServeDNSPreservesAnswersFromRouter(t *testing.T) {
	cfg := &config.Config{
		Hosts: map[string]string{
			"example.com": "1.2.3.4",
		},
		Rules: map[string]string{},
	}

	handler := &DNSRequestHandler{
		router: router.NewRouter(cfg, nil, nil),
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	writer := &captureResponseWriter{}
	handler.ServeDNS(writer, req)

	if writer.msg == nil {
		t.Fatal("expected a DNS response")
	}
	if writer.msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected RcodeSuccess, got %d", writer.msg.Rcode)
	}
	if len(writer.msg.Answer) != 1 {
		t.Fatalf("expected one answer, got %d", len(writer.msg.Answer))
	}

	a, ok := writer.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", writer.msg.Answer[0])
	}
	if !a.A.Equal(net.ParseIP("1.2.3.4").To4()) {
		t.Fatalf("expected 1.2.3.4, got %s", a.A)
	}
}
