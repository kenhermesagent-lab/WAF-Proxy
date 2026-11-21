package metrics

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseDefaultRoute(t *testing.T) {
	const table = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
eth1	00000000	0102A8C0	0003	0	0	50	00000000	0	0	0
eth0	0001A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
docker0	00000000	00000000	0001	0	0	0	00000000	0	0	0
`
	if got := parseDefaultRoute(strings.NewReader(table)); got != "eth1" {
		t.Errorf("parseDefaultRoute = %q, want eth1 (lowest physical metric)", got)
	}
}

func TestParseDefaultRouteVirtualOnly(t *testing.T) {
	const table = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
docker0	00000000	00000000	0001	0	0	0	00000000	0	0	0
`
	if got := parseDefaultRoute(strings.NewReader(table)); got != "docker0" {
		t.Errorf("parseDefaultRoute = %q, want docker0 when it is the only default route", got)
	}
}

func TestParseDefaultRouteEmpty(t *testing.T) {
	if got := parseDefaultRoute(strings.NewReader("Iface\tDestination\tGateway\n")); got != "" {
		t.Errorf("parseDefaultRoute = %q, want empty", got)
	}
}

func TestCountingConnCountsBothDirections(t *testing.T) {
	var in, out atomic.Uint64
	client, server := net.Pipe()
	defer client.Close()
	conn := &countingConn{Conn: server, in: &in, out: &out}

	go func() { _, _ = client.Write([]byte("hello")) }()
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil || n != 5 {
		t.Fatalf("Read = %d, %v; want 5 bytes", n, err)
	}
	if got := in.Load(); got != 5 {
		t.Errorf("inbound counter = %d, want 5", got)
	}

	written := make(chan struct{})
	go func() {
		_, _ = conn.Write([]byte("ok"))
		close(written)
	}()
	m, err := client.Read(buf)
	<-written
	if err != nil || m != 2 {
		t.Fatalf("client Read = %d, %v; want 2 bytes", m, err)
	}
	if got := out.Load(); got != 2 {
		t.Errorf("outbound counter = %d, want 2", got)
	}
}

func TestSplitSeparatesProxyFromHost(t *testing.T) {
	c := New("", "")
	now := time.Now()

	c.wan = Iface{RxBps: 100, TxBps: 50, RxTot: 1000, TxTot: 500}
	c.wireIn.Store(140)
	c.wireOut.Store(10)
	c.mu.Lock()
	c.splitLocked(now)
	c.mu.Unlock()

	if c.proxy != (Flow{InTot: 140, OutTot: 10}) {
		t.Errorf("first proxy flow = %+v, want totals 140/10 and no rate", c.proxy)
	}
	if c.host.InTot != 860 || c.host.OutTot != 490 {
		t.Errorf("first host totals = %+v, want 860/490", c.host)
	}
	if c.host.InBps != 100 || c.host.OutBps != 50 {
		t.Errorf("first host rates = %+v, want the whole interface", c.host)
	}

	c.wan = Iface{RxBps: 90, TxBps: 40, RxTot: 1090, TxTot: 540}
	c.wireIn.Store(240)
	c.wireOut.Store(60)
	c.mu.Lock()
	c.splitLocked(now.Add(time.Second))
	c.mu.Unlock()

	if c.proxy.InBps != 100 || c.proxy.OutBps != 50 {
		t.Errorf("proxy rates = %+v, want 100/50 for one second", c.proxy)
	}
	// The proxy cannot exceed the interface for the same second, so the host
	// share floors at zero instead of going negative.
	if c.host.InBps != 0 || c.host.OutBps != 0 {
		t.Errorf("host rates = %+v, want 0 when the proxy already covers the link", c.host)
	}
	if c.host.InTot != 850 || c.host.OutTot != 480 {
		t.Errorf("host totals = %+v, want 850/480", c.host)
	}
}

func TestIsVirtualInterface(t *testing.T) {
	cases := map[string]bool{
		"eth0":       false,
		"enp3s0":     false,
		"br0":        false,
		"tailscale0": false,
		"docker0":    true,
		"veth12a":    true,
		"virbr0":     true,
		"dummy0":     true,
	}
	for name, want := range cases {
		if got := isVirtualInterface(name); got != want {
			t.Errorf("isVirtualInterface(%q) = %v, want %v", name, got, want)
		}
	}
}
