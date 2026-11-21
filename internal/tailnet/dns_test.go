package tailnet

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func testDNS(t *testing.T, hosts HostSource) (*DNS, string) {
	t.Helper()
	d := NewDNS("127.0.0.1:0", hosts, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d, d.UDPAddr()
}

func query(t *testing.T, addr, name string, typ uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), typ)
	c := &dns.Client{Timeout: 2 * time.Second}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query %s: %v", name, err)
	}
	return resp
}

func TestDNSAnswersConfiguredHost(t *testing.T) {
	_, addr := testDNS(t, func() ([]string, error) {
		return []string{"App.Example.com."}, nil
	})
	resp := query(t, addr, "app.example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("rcode=%d answers=%d", resp.Rcode, len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("unexpected answer: %#v", resp.Answer[0])
	}
}

func TestDNSDoesNotResolveUnknownOrOtherTypes(t *testing.T) {
	_, addr := testDNS(t, func() ([]string, error) {
		return []string{"app.example.com"}, nil
	})
	if resp := query(t, addr, "other.example.com", dns.TypeA); resp.Rcode != dns.RcodeNameError {
		t.Fatalf("unknown name rcode = %d, want NXDOMAIN", resp.Rcode)
	}
	if resp := query(t, addr, "app.example.com", dns.TypeAAAA); resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("AAAA rcode=%d answers=%d, want empty success", resp.Rcode, len(resp.Answer))
	}
}

func TestDNSFailsClosedWhenHostsUnavailable(t *testing.T) {
	_, addr := testDNS(t, func() ([]string, error) {
		return nil, net.ErrClosed
	})
	if resp := query(t, addr, "app.example.com", dns.TypeA); resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL", resp.Rcode)
	}
}
