package metrics

import (
	"net"
	"os"
	"path/filepath"
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

func TestParseProcStatCountsBusyOnly(t *testing.T) {
	const stat = "cpu  100 20 30 800 50 5 5 0 0 0\ncpu0 1 2 3 4 5 6 7 8\nintr 7\n"
	busy, total, ok := parseProcStat(strings.NewReader(stat))
	if !ok || busy != 160 || total != 1010 {
		t.Fatalf("parseProcStat = %d/%d ok=%v, want 160/1010", busy, total, ok)
	}
}

func TestParseMeminfoSubtractsAvailable(t *testing.T) {
	const mem = "MemTotal:        8000000 kB\nMemFree:         1000000 kB\nMemAvailable:    3000000 kB\n"
	used, total, ok := parseMeminfo(strings.NewReader(mem))
	if !ok || total != 8000000*1024 || used != 5000000*1024 {
		t.Fatalf("parseMeminfo = %d/%d ok=%v, want 5000000/8000000 kB", used, total, ok)
	}
}

// The state is the token after the timeout; [ASSURED] and [UNREPLIED] are
// flags, and a stateless protocol has no state field at all.
func TestParseConntrackReadsTheStateToken(t *testing.T) {
	const table = `ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.10 dst=1.1.1.1 sport=56912 dport=443 src=1.1.1.1 dst=192.168.1.10 sport=443 dport=56912 [ASSURED] mark=0 use=2
ipv4     2 tcp      6 117 ESTABLISHED src=192.168.1.10 dst=1.1.1.1 sport=56913 dport=443 src=1.1.1.1 dst=192.168.1.10 sport=443 dport=56913 [ASSURED] mark=0 use=1
ipv4     2 tcp      6 117 TIME_WAIT src=192.168.1.10 dst=1.1.1.1 sport=56914 dport=443 src=1.1.1.1 dst=192.168.1.10 sport=443 dport=56914 [ASSURED] mark=0 use=1
ipv4     2 udp     17 29 src=192.168.1.10 dst=8.8.8.8 sport=5353 dport=53 src=8.8.8.8 dst=192.168.1.10 sport=53 dport=5353 mark=0 use=1
ipv4     2 icmp    1 30 src=192.168.1.10 dst=1.1.1.1 type=8 code=0 id=4211 [UNREPLIED] src=1.1.1.1 dst=192.168.1.10 type=0 code=0 id=4211 mark=0 use=1
`
	s := parseConntrack(strings.NewReader(table))
	if !s.Available || !s.States {
		t.Fatalf("available = %v, states = %v, want both true", s.Available, s.States)
	}
	if s.Active != 5 || s.Established != 2 || s.TimeWait != 1 {
		t.Fatalf("active = %d, established = %d, time_wait = %d, want 5, 2, 1", s.Active, s.Established, s.TimeWait)
	}
}

func TestReadConntrackCount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nf_conntrack_count")
	if err := os.WriteFile(path, []byte("742\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if n, ok := readConntrackCount(path); !ok || n != 742 {
		t.Fatalf("readConntrackCount = %d, %v, want 742, true", n, ok)
	}
	if _, ok := readConntrackCount(filepath.Join(t.TempDir(), "missing")); ok {
		t.Fatal("a missing count file reported a count")
	}
	garbage := filepath.Join(t.TempDir(), "nf_conntrack_count")
	if err := os.WriteFile(garbage, []byte("garbage\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, ok := readConntrackCount(garbage); ok {
		t.Fatal("an unparseable count file reported a count")
	}
}
