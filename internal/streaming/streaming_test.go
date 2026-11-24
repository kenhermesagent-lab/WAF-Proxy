package streaming

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Statuses moves its counters with traffic, keeps a last-seen time per session
// and files refusals under the reason that produced them.
func TestStatusesCountTrafficAndRefusals(t *testing.T) {
	up := echoServer(t)
	defer up.Close()
	upstream := fmt.Sprintf("127.0.0.1:%d", up.Addr().(*net.TCPAddr).Port)
	m := New(discardLogger())
	defer m.Close()

	listen := freePort(t)
	if err := m.Apply("plex", Config{Enabled: true, ListenIP: "127.0.0.1", Port: listen, Upstream: upstream}); err != nil {
		t.Fatal(err)
	}
	plex := func() Status {
		for _, st := range m.Statuses() {
			if st.ID == "plex" {
				return st
			}
		}
		t.Fatal("plex is missing from Statuses")
		return Status{}
	}

	conn := dialRelay(t, listen)
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the forwarded traffic to reach the status", func() bool {
		st := plex()
		return st.Total == 1 && st.BytesIn >= 5 && st.BytesOut >= 5 && len(st.Sessions) == 1
	})
	if s := plex().Sessions[0]; s.LastSeen.IsZero() || s.LastSeen.Before(s.Started) {
		t.Fatalf("session last seen = %v, started %v", s.LastSeen, s.Started)
	}

	// A source the port does not allow files one refusal under "allow".
	if err := m.Apply("plex", Config{Enabled: true, ListenIP: "127.0.0.1", Port: listen, Upstream: upstream,
		Allow: []string{"10.9.9.9/32"}}); err != nil {
		t.Fatal(err)
	}
	refused := dialRelay(t, listen)
	_ = refused.Close()
	waitFor(t, "the refusal reason", func() bool { return plex().RefusedByReason["allow"] == 1 })
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func echoServer(t *testing.T) net.Listener {
	t.Helper()
	return echoServerAt(t, 0)
}

// echoServerAt binds an echo server on one port, so a test can build a
// consecutive upstream range.
func echoServerAt(t *testing.T, port int) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("echo server on port %d: %v", port, err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln
}

// freePortRange finds n consecutive free TCP ports and releases them.
func freePortRange(t *testing.T, n int) int {
	t.Helper()
	for attempt := 0; attempt < 200; attempt++ {
		base := freePort(t)
		if base+n-1 > 65535 {
			continue
		}
		lns := make([]net.Listener, 0, n)
		for i := 0; i < n; i++ {
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", base+i))
			if err != nil {
				break
			}
			lns = append(lns, ln)
		}
		for _, ln := range lns {
			_ = ln.Close()
		}
		if len(lns) == n {
			return base
		}
	}
	t.Fatalf("no run of %d free TCP ports", n)
	return 0
}

// freePortBoth finds a number a TCP listener and a UDP socket can both bind.
func freePortBoth(t *testing.T) int {
	t.Helper()
	for attempt := 0; attempt < 200; attempt++ {
		port := freePort(t)
		pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			continue
		}
		_ = pc.Close()
		return port
	}
	t.Fatalf("no free TCP+UDP port")
	return 0
}

// eventLog is a thread-safe sink for assertions.
type eventLog struct {
	mu   sync.Mutex
	seen []Event
}

func (l *eventLog) sink() func(Event) {
	return func(ev Event) {
		l.mu.Lock()
		l.seen = append(l.seen, ev)
		l.mu.Unlock()
	}
}

func (l *eventLog) all() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Event(nil), l.seen...)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func dialRelay(t *testing.T, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

func TestForwarderRelaysAndCounts(t *testing.T) {
	upstream := echoServer(t)
	defer upstream.Close()
	m := New(discardLogger())
	defer m.Close()

	port := freePort(t)
	if err := m.Apply("plex", Config{Enabled: true, ListenIP: "127.0.0.1", Port: port, Upstream: upstream.Addr().String()}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	st := m.Statuses()[0]
	if st.ID != "plex" || !st.Bound || st.ListenAddr == "" {
		t.Fatalf("status = %+v, want a bound plex listener", st)
	}
	// The unconfigured service is still reported so the page can render it.
	if jf := m.Statuses()[1]; jf.ID != "jellyfin" || jf.Bound || jf.Enabled {
		t.Fatalf("jellyfin status = %+v, want an unconfigured entry", jf)
	}

	conn := dialRelay(t, port)
	defer conn.Close()
	if _, err := conn.Write([]byte("stream-bytes")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("stream-bytes"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "stream-bytes" {
		t.Fatalf("echo = %q", buf)
	}
	waitFor(t, "one accepted stream", func() bool { return m.Statuses()[0].Total == 1 })
}

func TestForwarderAllowListBlocks(t *testing.T) {
	upstream := echoServer(t)
	defer upstream.Close()
	m := New(discardLogger())
	defer m.Close()

	port := freePort(t)
	if err := m.Apply("jellyfin", Config{Enabled: true, ListenIP: "127.0.0.1", Port: port,
		Upstream: upstream.Addr().String(), Allow: []string{"198.51.100.0/24"}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	conn := dialRelay(t, port)
	defer conn.Close()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection was not closed by the allow list")
	}
	waitFor(t, "a blocked counter", func() bool { return m.Statuses()[1].Blocked == 1 })
}

func TestForwarderRefusesBannedSources(t *testing.T) {
	upstream := echoServer(t)
	defer upstream.Close()
	m := New(discardLogger())
	defer m.Close()
	m.SetBans(func(addr netip.Addr) bool { return addr == netip.MustParseAddr("127.0.0.1") })

	port := freePort(t)
	if err := m.Apply("plex", Config{Enabled: true, ListenIP: "127.0.0.1", Port: port, Upstream: upstream.Addr().String()}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	conn := dialRelay(t, port)
	defer conn.Close()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a banned source was not refused")
	}
	waitFor(t, "one ban refusal", func() bool { return m.Statuses()[0].Banned == 1 })
	if total := m.Statuses()[0].Total; total != 0 {
		t.Fatalf("total = %d, want no accepted connection", total)
	}
}

// A banned host that keeps retrying must not produce one event per attempt, but
// the counters still move and the next window reports how many it folded in.
func TestBannedRetriesAreThrottled(t *testing.T) {
	upstream := echoServer(t)
	defer upstream.Close()

	clock := time.Now()
	var clockMu sync.Mutex
	m := New(discardLogger())
	defer m.Close()
	m.now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return clock
	}
	m.SetBans(func(netip.Addr) bool { return true })
	log := &eventLog{}
	m.SetEventSink(log.sink())

	port := freePort(t)
	if err := m.Apply("plex", Config{Enabled: true, ListenIP: "127.0.0.1", Port: port, Upstream: upstream.Addr().String()}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	for i := 0; i < 20; i++ {
		conn := dialRelay(t, port)
		_, _ = conn.Read(make([]byte, 1))
		conn.Close()
	}
	waitFor(t, "20 refusals", func() bool { return m.Statuses()[0].Banned == 20 })

	if got := len(log.all()); got != 1 {
		t.Fatalf("events = %d, want 1 for 20 attempts in the same window", got)
	}

	// The next attempt after the window reports the folded count once.
	clockMu.Lock()
	clock = clock.Add(refusalWindow + time.Second)
	clockMu.Unlock()

	conn := dialRelay(t, port)
	_, _ = conn.Read(make([]byte, 1))
	conn.Close()
	waitFor(t, "21 refusals", func() bool { return m.Statuses()[0].Banned == 21 })

	events := log.all()
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2 after the window rolled", len(events))
	}
	if want := "19 more attempts suppressed"; !strings.Contains(events[1].Detail, want) {
		t.Fatalf("detail = %q, want it to mention %q", events[1].Detail, want)
	}
}

func TestDropBannedCutsOpenStreams(t *testing.T) {
	upstream := echoServer(t)
	defer upstream.Close()
	m := New(discardLogger())
	defer m.Close()
	log := &eventLog{}
	m.SetEventSink(log.sink())

	port := freePort(t)
	if err := m.Apply("plex", Config{Enabled: true, ListenIP: "127.0.0.1", Port: port, Upstream: upstream.Addr().String()}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	conn := dialRelay(t, port)
	defer conn.Close()
	if _, err := conn.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		t.Fatalf("stream not established: %v", err)
	}

	cut := m.DropBanned(func(addr netip.Addr) bool { return addr == netip.MustParseAddr("127.0.0.1") },
		"stream closed by ban 127.0.0.1/32")
	if cut != 1 {
		t.Fatalf("DropBanned cut %d streams, want 1", cut)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the open stream still delivered data after the ban")
	}
	waitFor(t, "the drop counter", func() bool { return m.Statuses()[0].Dropped == 1 })

	events := log.all()
	if len(events) != 1 || events[0].Service != "plex" || events[0].Detail != "stream closed by ban 127.0.0.1/32" {
		t.Fatalf("events = %+v, want one plex drop event", events)
	}
}

func TestForwarderDisableStopsListener(t *testing.T) {
	m := New(discardLogger())
	defer m.Close()
	port := freePort(t)
	upstream := echoServer(t)
	defer upstream.Close()
	base := Config{ListenIP: "127.0.0.1", Port: port, Upstream: upstream.Addr().String()}

	enabled, disabled := base, base
	enabled.Enabled = true
	if err := m.Apply("plex", enabled); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := m.Apply("plex", disabled); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if st := m.Statuses()[0]; st.Bound {
		t.Fatalf("status = %+v, want a stopped forwarder", st)
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("listener still accepting after disable")
	}
}

func TestApplyKeepsOtherServices(t *testing.T) {
	upstream := echoServer(t)
	defer upstream.Close()
	m := New(discardLogger())
	defer m.Close()

	plexPort, jfPort := freePort(t), freePort(t)
	if err := m.Apply("plex", Config{Enabled: true, ListenIP: "127.0.0.1", Port: plexPort, Upstream: upstream.Addr().String()}); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply("jellyfin", Config{Enabled: true, ListenIP: "127.0.0.1", Port: jfPort, Upstream: upstream.Addr().String()}); err != nil {
		t.Fatal(err)
	}
	// Rebinding Plex must not disturb Jellyfin.
	if err := m.Apply("plex", Config{Enabled: false, ListenIP: "127.0.0.1", Port: plexPort, Upstream: upstream.Addr().String()}); err != nil {
		t.Fatal(err)
	}
	statuses := m.Statuses()
	if statuses[0].Bound {
		t.Fatal("plex still bound after disable")
	}
	if !statuses[1].Bound {
		t.Fatal("jellyfin lost its listener when plex was reapplied")
	}
}

func TestUnknownServiceIsRejected(t *testing.T) {
	m := New(discardLogger())
	defer m.Close()
	if err := m.Apply("emby", Config{Enabled: true, Upstream: "127.0.0.1:8096"}); err == nil {
		t.Fatal("expected an error for an unsupported service")
	}
}

func TestNormalize(t *testing.T) {
	plex, _ := Lookup("plex")
	jf, _ := Lookup("jellyfin")
	cases := []struct {
		name    string
		def     Service
		in      Config
		want    Config
		wantErr bool
	}{
		{
			name: "plex defaults",
			def:  plex,
			in:   Config{Upstream: "10.0.0.10"},
			want: Config{Port: 32400, Upstream: "10.0.0.10:32400", MaxConns: DefaultMaxConns},
		},
		{
			name: "jellyfin default port",
			def:  jf,
			in:   Config{Upstream: "10.0.0.11"},
			want: Config{Port: 8096, Upstream: "10.0.0.11:8096", MaxConns: DefaultMaxConns},
		},
		{
			name: "strips scheme",
			def:  plex,
			in:   Config{Upstream: "http://10.0.0.10:32400/"},
			want: Config{Port: 32400, Upstream: "10.0.0.10:32400", MaxConns: DefaultMaxConns},
		},
		{
			name: "normalises allow entries",
			def:  plex,
			in:   Config{Upstream: "plex.lan:32400", Allow: []string{"10.0.0.10", "10.0.0.0/8"}},
			want: Config{Port: 32400, Upstream: "plex.lan:32400", MaxConns: DefaultMaxConns,
				Allow: []string{"10.0.0.10/32", "10.0.0.0/8"}},
		},
		{name: "missing upstream", def: plex, in: Config{}, wantErr: true},
		{name: "pasted sentence", def: plex, in: Config{Upstream: "not a url"}, wantErr: true},
		{name: "url with empty host", def: plex, in: Config{Upstream: "http://"}, wantErr: true},
		{name: "bad port", def: plex, in: Config{Upstream: "plex.lan", Port: 70000}, wantErr: true},
		{name: "bad allow entry", def: plex, in: Config{Upstream: "plex.lan", Allow: []string{"not-an-ip"}}, wantErr: true},
	}
	for _, c := range cases {
		got, err := c.in.Normalize(c.def)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: expected an error", c.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got.Port != c.want.Port || got.Upstream != c.want.Upstream || got.MaxConns != c.want.MaxConns {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
		if len(c.want.Allow) > 0 && fmt.Sprint(got.Allow) != fmt.Sprint(c.want.Allow) {
			t.Errorf("%s: allow = %v, want %v", c.name, got.Allow, c.want.Allow)
		}
	}
}

// 1.60 saved only port, upstream and the caps. Those settings must still load
// as one TCP port, exactly as they behaved then.
func TestConfigFromSettingsLegacyKeys(t *testing.T) {
	plex, _ := Lookup("plex")
	got := ConfigFromSettings(plex, map[string]string{
		"plex_enabled": "1", "plex_listen_ip": "192.168.1.2", "plex_port": "32402",
		"plex_upstream": "10.0.0.10:32400", "plex_allow": "10.0.0.0/8", "plex_max_conns": "64",
	})
	if got.Protocol != "tcp" || got.PortCount != 1 || got.Port != 32402 || got.MaxConns != 64 {
		t.Fatalf("legacy config = %+v, want one tcp port with the saved caps", got)
	}
	if got.UpstreamPort != 0 || got.MaxPerSource != DefaultMaxPerSource ||
		got.IdleSeconds != DefaultUDPIdleSeconds || got.MaxDatagram != DefaultMaxDatagram {
		t.Fatalf("legacy defaults = %+v", got)
	}
	norm, err := got.Normalize(plex)
	if err != nil {
		t.Fatal(err)
	}
	if norm.Upstream != "10.0.0.10:32400" || norm.UpstreamPort != 32400 || norm.Protocol != "tcp" {
		t.Fatalf("normalized = %+v, want the saved upstream kept", norm)
	}
}

// A 1.63 key wins over the bare plex_* fallback it replaced.
func TestConfigFromSettingsNewKeysWin(t *testing.T) {
	plex, _ := Lookup("plex")
	got := ConfigFromSettings(plex, map[string]string{
		"plex_port": "32400", "plex_upstream": "10.0.0.10:32400",
		"stream_plex_port": "2456", "stream_plex_protocol": "UDP", "stream_plex_port_count": "3",
		"stream_plex_upstream": "10.0.0.20:2456", "stream_plex_upstream_port": "2457",
		"stream_plex_max_per_source": "4", "stream_plex_idle_seconds": "90",
		"stream_plex_max_datagram": "1200",
	})
	if got.Protocol != "udp" || got.Port != 2456 || got.PortCount != 3 || got.UpstreamPort != 2457 {
		t.Fatalf("config = %+v, want the 1.63 keys", got)
	}
	if got.MaxPerSource != 4 || got.IdleSeconds != 90 || got.MaxDatagram != 1200 {
		t.Fatalf("udp limits = %+v", got)
	}
}

func TestNormalizePortRanges(t *testing.T) {
	custom, _ := Lookup("custom")
	valid := []Config{
		{Upstream: "10.0.0.5:2456", Port: 2456, PortCount: 3, Protocol: "udp"},
		{Upstream: "10.0.0.5:25565", Port: 25565, PortCount: 2, Protocol: "tcp"},
		{Upstream: "10.0.0.5:30120", Port: 30120, Protocol: "both"},
		{Upstream: "10.0.0.5:26900", Port: 26900, PortCount: 4, Protocol: "both"},
	}
	for _, in := range valid {
		if _, err := in.Normalize(custom); err != nil {
			t.Errorf("%+v: %v", in, err)
		}
	}

	bad := []struct {
		name string
		in   Config
	}{
		{name: "unknown protocol", in: Config{Upstream: "h:2456", Protocol: "sctp"}},
		{name: "count 17", in: Config{Upstream: "h:2456", PortCount: 17}},
		{name: "port 70000", in: Config{Upstream: "h:2456", Port: 70000}},
		{name: "listen range crossing 65535", in: Config{Upstream: "h:2456", Port: 65535, PortCount: 2}},
		{name: "upstream range crossing 65535", in: Config{Upstream: "h:65535", Port: 2456, PortCount: 2}},
		{name: "upstream port 0", in: Config{Upstream: "h:0", Port: 2456}},
	}
	for _, c := range bad {
		if _, err := c.in.Normalize(custom); err == nil {
			t.Errorf("%s: expected an error", c.name)
		}
	}

	// A zero count means one port, not an error.
	got, err := Config{Upstream: "h:2456", Port: 2456, Protocol: "both"}.Normalize(custom)
	if err != nil {
		t.Fatal(err)
	}
	if got.PortCount != 1 || got.UpstreamPort != 2456 {
		t.Fatalf("normalized = %+v, want one port mapped to 2456", got)
	}
}

// A TCP range listens on N ports and forwards each to its own upstream port,
// so a game that opens several TCP ports is one card.
func TestTCPPortRangeMapsOneToOne(t *testing.T) {
	const n = 3
	upBase := freePortRange(t, n)
	for i := 0; i < n; i++ {
		up := echoServerAt(t, upBase+i)
		defer up.Close()
	}
	listenBase := freePortRange(t, n)

	m := New(discardLogger())
	defer m.Close()
	if err := m.Apply("custom", Config{Enabled: true, Protocol: "tcp", ListenIP: "127.0.0.1",
		Port: listenBase, PortCount: n, Upstream: fmt.Sprintf("127.0.0.1:%d", upBase)}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	st := m.Statuses()[2]
	want := fmt.Sprintf("127.0.0.1:%d-%d", listenBase, listenBase+n-1)
	if !st.Bound || st.PortCount != n || st.ListenAddr != want {
		t.Fatalf("status = %+v, want a bound range %s", st, want)
	}
	if st.UpstreamBase != fmt.Sprintf("127.0.0.1:%d", upBase) {
		t.Fatalf("upstream_base = %q", st.UpstreamBase)
	}

	for i := 0; i < n; i++ {
		conn := dialRelay(t, listenBase+i)
		payload := fmt.Sprintf("port-%d", listenBase+i)
		if _, err := conn.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read on port %d: %v", listenBase+i, err)
		}
		if string(buf) != payload {
			t.Fatalf("echo = %q, want %q", buf, payload)
		}
		conn.Close()
	}
	waitFor(t, "three accepted streams", func() bool { return m.Statuses()[2].Total == 3 })
}

// "both" binds a TCP listener and a UDP socket on one number and reports a
// single status; traffic flows on either protocol.
func TestBothProtocolBindsTwoSockets(t *testing.T) {
	tcpUp := echoServer(t)
	defer tcpUp.Close()
	upPort := tcpUp.Addr().(*net.TCPAddr).Port
	// The UDP upstream shares the number: the two protocols do not collide.
	newUDPEcho(t, upPort, "")

	listen := freePortBoth(t)
	m := New(discardLogger())
	defer m.Close()
	if err := m.Apply("custom", Config{Enabled: true, Protocol: "both", ListenIP: "127.0.0.1",
		Port: listen, Upstream: fmt.Sprintf("127.0.0.1:%d", upPort)}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	rt := m.services["custom"]
	if rt == nil || len(rt.listeners) != 1 || rt.udp == nil {
		t.Fatalf("runtime = %+v, want one TCP listener and one UDP socket", rt)
	}
	st := m.Statuses()[2]
	if !st.Bound || st.Protocol != "both" || !strings.Contains(st.ListenAddr, "tcp+udp") {
		t.Fatalf("status = %+v, want both protocols bound on one status", st)
	}

	conn := dialRelay(t, listen)
	defer conn.Close()
	if _, err := conn.Write([]byte("tcp")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 3)); err != nil {
		t.Fatalf("tcp half: %v", err)
	}

	client := udpClient(t, listen)
	sendUDP(t, client, "udp")
	expectReply(t, client, "udp")

	waitFor(t, "both protocols counted", func() bool {
		s := m.Statuses()[2]
		return s.Active == 1 && s.ActiveSessions == 1 && s.Total == 2 && s.BytesIn > 0
	})
	waitFor(t, "both sessions listed", func() bool { return len(m.Statuses()[2].Sessions) == 2 })
}

// A "both" service whose UDP port is taken still serves TCP, but is not
// reported as bound and names the protocol that failed.
func TestBothPartialFailureNamesTheProtocol(t *testing.T) {
	up := echoServer(t)
	defer up.Close()
	port := freePort(t)
	taken, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()

	m := New(discardLogger())
	defer m.Close()
	err = m.Apply("custom", Config{Enabled: true, Protocol: "both", ListenIP: "127.0.0.1",
		Port: port, Upstream: up.Addr().String()})
	if err == nil {
		t.Fatal("expected the udp bind error")
	}
	if !strings.Contains(err.Error(), "/udp") {
		t.Fatalf("error = %v, want it to name udp", err)
	}
	st := m.Statuses()[2]
	if st.Bound || !strings.Contains(st.LastError, "/udp") {
		t.Fatalf("status = %+v, want unbound with the udp error", st)
	}

	conn := dialRelay(t, port)
	defer conn.Close()
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		t.Fatalf("the tcp half did not relay: %v", err)
	}
}
