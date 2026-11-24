package streaming

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// freeUDPRange finds n consecutive free UDP ports and releases them, so a test
// can ask for a real range like Valheim's 2456-2458.
func freeUDPRange(t *testing.T, n int) int {
	t.Helper()
	for attempt := 0; attempt < 200; attempt++ {
		base := freeUDPPort(t)
		if base < 1024 || base+n-1 > 65535 {
			continue
		}
		conns := make([]*net.UDPConn, 0, n)
		for i := 0; i < n; i++ {
			pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: base + i})
			if err != nil {
				break
			}
			conns = append(conns, pc)
		}
		for _, pc := range conns {
			_ = pc.Close()
		}
		if len(conns) == n {
			return base
		}
	}
	t.Fatalf("no run of %d free UDP ports", n)
	return 0
}

// udpEcho answers from the socket it received on, with tag prefixed, so a test
// can tell which upstream port replied.
type udpEcho struct {
	conn *net.UDPConn
	got  atomic.Int64
}

func newUDPEcho(t *testing.T, port int, tag string) *udpEcho {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatalf("echo server on port %d: %v", port, err)
	}
	e := &udpEcho{conn: pc}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			e.got.Add(1)
			reply := append([]byte(tag), buf[:n]...)
			_, _ = pc.WriteToUDP(reply, from)
		}
	}()
	return e
}

func (e *udpEcho) addr() string {
	return net.JoinHostPort("127.0.0.1", fmt.Sprint(e.conn.LocalAddr().(*net.UDPAddr).Port))
}

func udpClient(t *testing.T, port int) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func sendUDP(t *testing.T, c *net.UDPConn, payload string) {
	t.Helper()
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatalf("send %q: %v", payload, err)
	}
}

func expectReply(t *testing.T, c *net.UDPConn, want string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read reply (want %q): %v", want, err)
	}
	if got := string(buf[:n]); got != want {
		t.Fatalf("reply = %q, want %q", got, want)
	}
	_ = c.SetReadDeadline(time.Time{})
}

func expectNoReply(t *testing.T, c *net.UDPConn, what string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 4096)
	if n, err := c.Read(buf); err == nil {
		t.Fatalf("%s: a reply arrived: %q", what, buf[:n])
	}
	_ = c.SetReadDeadline(time.Time{})
}

func applyUDP(t *testing.T, m *Manager, id string, cfg Config) *udpRuntime {
	t.Helper()
	cfg.Enabled = true
	cfg.Protocol = "udp"
	cfg.ListenIP = "127.0.0.1"
	if err := m.Apply(id, cfg); err != nil {
		t.Fatalf("apply %s: %v", id, err)
	}
	u := m.services[id].udp
	if u == nil {
		t.Fatalf("%s has no UDP runtime", id)
	}
	return u
}

func TestUDPEchoRelaysAndCounts(t *testing.T) {
	up := newUDPEcho(t, 0, "")
	m := New(discardLogger())
	defer m.Close()

	listen := freeUDPPort(t)
	u := applyUDP(t, m, "plex", Config{Port: listen, Upstream: up.addr()})

	client := udpClient(t, listen)
	for i := 0; i < 20; i++ {
		payload := fmt.Sprintf("game-%02d", i)
		sendUDP(t, client, payload)
		expectReply(t, client, payload)
	}

	waitFor(t, "20 datagrams each way", func() bool {
		return u.pktsIn.Load() == 20 && u.pktsOut.Load() == 20
	})
	if in, out := u.bytesIn.Load(), u.bytesOut.Load(); in == 0 || in != out {
		t.Fatalf("byte counters in=%d out=%d, want equal and non-zero", in, out)
	}
	st := m.Statuses()[0]
	if !st.Bound || st.ListenAddr == "" {
		t.Fatalf("status = %+v, want a bound UDP listener", st)
	}
	if st.ActiveSessions != 1 || st.Active != 0 || st.Total != 1 {
		t.Fatalf("status = %+v, want one active session and no TCP connections", st)
	}
}

// A count-3 service maps listen port N to upstream port N, so Valheim's three
// ports are one card rather than three listeners with guessed offsets.
func TestUDPPortRangeMapsOneToOne(t *testing.T) {
	const n = 3
	upBase := freeUDPRange(t, n)
	listenBase := freeUDPRange(t, n)
	for i := 0; i < n; i++ {
		newUDPEcho(t, upBase+i, fmt.Sprintf("%d|", upBase+i))
	}

	m := New(discardLogger())
	defer m.Close()
	u := applyUDP(t, m, "plex", Config{Port: listenBase, PortCount: n,
		Upstream: fmt.Sprintf("127.0.0.1:%d", upBase)})
	if got, want := u.listenAddr(), fmt.Sprintf("127.0.0.1:%d-%d", listenBase, listenBase+n-1); got != want {
		t.Fatalf("listen address = %q, want %q", got, want)
	}

	for i := 0; i < n; i++ {
		client := udpClient(t, listenBase+i)
		sendUDP(t, client, "ping")
		expectReply(t, client, fmt.Sprintf("%d|ping", upBase+i))
	}

	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.sess) != n {
		t.Fatalf("sessions = %d, want one per listen port", len(u.sess))
	}
	for i := 0; i < n; i++ {
		found := false
		for k := range u.sess {
			if k.port == listenBase+i {
				found = true
			}
		}
		if !found {
			t.Fatalf("no session for listen port %d", listenBase+i)
		}
	}
}

// Each session has a connected upstream socket, so a datagram that reaches that
// socket from any other host is dropped by the kernel, never relayed.
func TestUDPConnectedSocketDropsForeignDatagrams(t *testing.T) {
	up := newUDPEcho(t, 0, "")
	m := New(discardLogger())
	defer m.Close()

	listen := freeUDPPort(t)
	u := applyUDP(t, m, "plex", Config{Port: listen, Upstream: up.addr()})
	client := udpClient(t, listen)
	sendUDP(t, client, "hello")
	expectReply(t, client, "hello")

	u.mu.Lock()
	var sess *udpSession
	for _, s := range u.sess {
		sess = s
	}
	u.mu.Unlock()
	if sess == nil {
		t.Fatal("no session after the echo")
	}

	attacker, err := net.DialUDP("udp", nil, sess.upstream.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()
	if _, err := attacker.Write([]byte("injected")); err != nil {
		t.Fatal(err)
	}

	expectNoReply(t, client, "a datagram from a foreign socket")
	if out := u.pktsOut.Load(); out != 1 {
		t.Fatalf("relayed %d replies, want only the legitimate one", out)
	}
}

// One address can open at most MaxPerSource sessions; the 9th on a default
// service is refused and the slot comes back when a session expires.
func TestUDPPerSourceSessionCap(t *testing.T) {
	up := newUDPEcho(t, 0, "")
	m := New(discardLogger())
	defer m.Close()
	log := &eventLog{}
	m.SetEventSink(log.sink())

	listen := freeUDPPort(t)
	u := applyUDP(t, m, "plex", Config{Port: listen, Upstream: up.addr()})

	for i := 0; i < DefaultMaxPerSource; i++ {
		client := udpClient(t, listen)
		sendUDP(t, client, "hi")
		expectReply(t, client, "hi")
	}
	waitFor(t, "8 sessions", func() bool { return u.active.Load() == int64(DefaultMaxPerSource) })

	blockedClient := udpClient(t, listen)
	sendUDP(t, blockedClient, "one too many")
	expectNoReply(t, blockedClient, "the 9th session")
	waitFor(t, "a cap refusal", func() bool { return u.blocked.Load() == 1 })
	events := log.all()
	if len(events) != 1 || events[0].Kind != "stream-cap" || events[0].Method != "UDP" {
		t.Fatalf("events = %+v, want one stream-cap UDP refusal", events)
	}

	// An idle sweep frees the slots; the next client gets in.
	u.sweepIdle(time.Now().Add(time.Hour))
	waitFor(t, "no sessions", func() bool { return u.active.Load() == 0 })
	fresh := udpClient(t, listen)
	sendUDP(t, fresh, "again")
	expectReply(t, fresh, "again")
}

func TestUDPIdleSessionsExpire(t *testing.T) {
	up := newUDPEcho(t, 0, "")
	m := New(discardLogger())
	defer m.Close()

	listen := freeUDPPort(t)
	u := applyUDP(t, m, "plex", Config{Port: listen, Upstream: up.addr()})
	client := udpClient(t, listen)
	sendUDP(t, client, "hi")
	expectReply(t, client, "hi")

	u.mu.Lock()
	var sess *udpSession
	for _, s := range u.sess {
		sess = s
	}
	u.mu.Unlock()
	if sess == nil {
		t.Fatal("no session after the echo")
	}
	idle := time.Duration(u.cfg.IdleSeconds) * time.Second

	// Still inside the window: nothing is touched.
	sess.lastSeen.Store(time.Now().Add(-idle + 5*time.Second).UnixNano())
	u.sweepIdle(time.Now())
	if got := u.active.Load(); got != 1 {
		t.Fatalf("active = %d, want the session kept", got)
	}

	// Two idle windows old, which is what the janitor sees after a game server
	// was switched off.
	sess.lastSeen.Store(time.Now().Add(-2 * idle).UnixNano())
	u.sweepIdle(time.Now())
	if got := u.active.Load(); got != 0 {
		t.Fatalf("active = %d after the idle sweep", got)
	}
	u.mu.Lock()
	sessions, perSource := len(u.sess), len(u.perSource)
	u.mu.Unlock()
	if sessions != 0 || perSource != 0 {
		t.Fatalf("sessions=%d per-source=%d, want both empty", sessions, perSource)
	}
	if _, err := sess.upstream.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("session socket read = %v, want net.ErrClosed", err)
	}
}

// A ban added while a session is live must cut it on the next datagram, and the
// refusal is logged once per throttle window rather than per packet.
func TestUDPBanCutsLiveSession(t *testing.T) {
	up := newUDPEcho(t, 0, "")
	m := New(discardLogger())
	defer m.Close()
	log := &eventLog{}
	m.SetEventSink(log.sink())
	var banned atomic.Bool
	m.SetBans(func(netip.Addr) bool { return banned.Load() })

	listen := freeUDPPort(t)
	u := applyUDP(t, m, "plex", Config{Port: listen, Upstream: up.addr()})
	client := udpClient(t, listen)
	sendUDP(t, client, "before")
	expectReply(t, client, "before")

	banned.Store(true)
	sendUDP(t, client, "after")
	expectNoReply(t, client, "a datagram from a banned source")
	waitFor(t, "the session cut and counted", func() bool {
		u.mu.Lock()
		n := len(u.sess)
		u.mu.Unlock()
		return n == 0 && u.banned.Load() == 1 && u.dropped.Load() == 1
	})

	events := log.all()
	if len(events) != 1 || events[0].Kind != "stream-ban" || events[0].Method != "UDP" || events[0].Port != listen {
		t.Fatalf("events = %+v, want one UDP ban refusal on port %d", events, listen)
	}

	sendUDP(t, client, "again")
	expectNoReply(t, client, "a second datagram from a banned source")
	waitFor(t, "the second refusal counted", func() bool { return u.banned.Load() == 2 })
	if got := len(log.all()); got != 1 {
		t.Fatalf("events = %d, want the repeat suppressed inside the window", got)
	}
}

// A datagram over the cap is dropped and counted, never truncated and sent on.
func TestUDPOversizedDatagramIsDropped(t *testing.T) {
	up := newUDPEcho(t, 0, "")
	m := New(discardLogger())
	defer m.Close()
	listen := freeUDPPort(t)
	u := applyUDP(t, m, "plex", Config{Port: listen, Upstream: up.addr(), MaxDatagram: 1500})

	client := udpClient(t, listen)
	sendUDP(t, client, strings.Repeat("x", 2000))
	expectNoReply(t, client, "an oversized datagram")
	waitFor(t, "an oversize drop", func() bool { return u.oversize.Load() == 1 })
	if got := up.got.Load(); got != 0 {
		t.Fatalf("the upstream received %d datagrams, want none", got)
	}
}

// Closing the manager closes the sessions and releases the port at once, which
// is what a demotion needs before the other node binds it.
func TestUDPCloseReleasesPortAndSessions(t *testing.T) {
	up := newUDPEcho(t, 0, "")
	listen := freeUDPPort(t)
	m := New(discardLogger())

	u := applyUDP(t, m, "plex", Config{Port: listen, Upstream: up.addr()})
	client := udpClient(t, listen)
	sendUDP(t, client, "hi")
	expectReply(t, client, "hi")

	u.mu.Lock()
	var sess *udpSession
	for _, s := range u.sess {
		sess = s
	}
	u.mu.Unlock()
	if sess == nil {
		t.Fatal("no session after the echo")
	}

	m.Close()
	if _, err := sess.upstream.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("session socket read = %v, want net.ErrClosed", err)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: listen})
	if err != nil {
		t.Fatalf("the UDP port was not released: %v", err)
	}
	_ = pc.Close()
}

// On a dual-stack socket a client arrives as an IPv4-mapped address. The
// per-source count is keyed on the plain address, so the session must decrement
// the key it incremented.
func TestUDPPerSourceCountUsesUnmappedAddress(t *testing.T) {
	up, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()

	mapped := netip.MustParseAddr("::ffff:203.0.113.7")
	plain := mapped.Unmap()
	u := &udpRuntime{sess: map[sessionKey]*udpSession{}, perSource: map[netip.Addr]int{}}
	s := &udpSession{key: sessionKey{addr: netip.AddrPortFrom(mapped, 5000), port: 2456}, addr: plain, upstream: up}
	u.sess[s.key] = s
	u.perSource[plain] = 1
	u.active.Store(1)

	u.drop(s)
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.perSource) != 0 {
		t.Fatalf("per-source table = %v, want the entry removed", u.perSource)
	}
	if got := u.active.Load(); got != 0 {
		t.Fatalf("active = %d, want 0", got)
	}
}

func TestUDPBindFailureIsReported(t *testing.T) {
	up := newUDPEcho(t, 0, "")
	listen := freeUDPPort(t)
	taken, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: listen})
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()

	m := New(discardLogger())
	defer m.Close()
	err = m.Apply("plex", Config{Enabled: true, Protocol: "udp", ListenIP: "127.0.0.1", Port: listen, Upstream: up.addr()})
	if err == nil {
		t.Fatal("expected a bind error for a port in use")
	}
	if st := m.Statuses()[0]; st.Bound || st.LastError == "" {
		t.Fatalf("status = %+v, want unbound with the bind error recorded", st)
	}
}

func TestUDPConfigNormalize(t *testing.T) {
	plex, _ := Lookup("plex")
	cfg, err := Config{Upstream: "10.0.0.5:2456", Port: 2456, PortCount: 3, Protocol: "UDP"}.Normalize(plex)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Protocol != "udp" || cfg.PortCount != 3 || cfg.UpstreamPort != 2456 || cfg.Upstream != "10.0.0.5:2456" {
		t.Fatalf("normalized = %+v, want udp on 2456-2458 to 2456-2458", cfg)
	}
	if cfg.MaxPerSource != DefaultMaxPerSource || cfg.IdleSeconds != DefaultUDPIdleSeconds || cfg.MaxDatagram != DefaultMaxDatagram {
		t.Fatalf("udp defaults = %+v", cfg)
	}

	bad := []struct {
		name string
		in   Config
	}{
		{name: "unknown protocol", in: Config{Upstream: "h:2456", Protocol: "sctp"}},
		{name: "count too large", in: Config{Upstream: "h:2456", Port: 2456, PortCount: 17, Protocol: "udp"}},
		{name: "listen range past 65535", in: Config{Upstream: "h:2456", Port: 65534, PortCount: 3, Protocol: "udp"}},
		{name: "upstream range past 65535", in: Config{Upstream: "h:65534", Port: 2456, PortCount: 3, Protocol: "udp"}},
		{name: "datagram too large", in: Config{Upstream: "h:2456", MaxDatagram: 9000}},
		{name: "idle too short", in: Config{Upstream: "h:2456", IdleSeconds: 5}},
	}
	for _, c := range bad {
		if _, err := c.in.Normalize(plex); err == nil {
			t.Errorf("%s: expected an error", c.name)
		}
	}
}

// The amplification ports and a privileged port are refused for the protocols
// that open a UDP socket, and allowed for TCP.
func TestNormalizeUDPPortSafety(t *testing.T) {
	custom, _ := Lookup("custom")
	for _, port := range []int{53, 123, 161, 389, 1900, 5353, 11211} {
		_, err := Config{Upstream: "10.0.0.5:2456", Port: port, Protocol: "udp"}.Normalize(custom)
		if err == nil || !strings.Contains(err.Error(), "amplification") {
			t.Errorf("udp port %d: err = %v, want an amplification refusal", port, err)
		}
		if _, err := (Config{Upstream: "10.0.0.5:2456", Port: port}).Normalize(custom); err != nil {
			t.Errorf("tcp port %d: %v", port, err)
		}
	}

	// A range that covers a denied port is refused, and the message names it.
	if _, err := (Config{Upstream: "10.0.0.5:2456", Port: 50, PortCount: 5, Protocol: "both"}).Normalize(custom); err == nil ||
		!strings.Contains(err.Error(), "53") {
		t.Errorf("range over 53: err = %v, want it to name port 53", err)
	}

	priv := Config{Upstream: "10.0.0.5:2456", Port: 443, Protocol: "udp"}
	// The message names the switch the operator sees on the card, not an
	// internal setting key.
	if _, err := priv.Normalize(custom); err == nil || !strings.Contains(err.Error(), "below 1024") ||
		!strings.Contains(err.Error(), "Refuse sources that are not on an allow list") {
		t.Errorf("privileged udp without a list: err = %v", err)
	}
	priv.RequireAllow = true
	if _, err := priv.Normalize(custom); err == nil {
		t.Error("a privileged udp port with no allowed source was accepted")
	}
	priv.Allow = []string{"10.0.0.0/8"}
	if _, err := priv.Normalize(custom); err != nil {
		t.Errorf("privileged udp with a list: %v", err)
	}

	// TCP on 443 is the proxy's own number and keeps working.
	if _, err := (Config{Upstream: "10.0.0.5:443", Port: 443}).Normalize(custom); err != nil {
		t.Errorf("tcp 443: %v", err)
	}
}

// A port with the allow requirement and no list refuses every session, and a
// whitelist or an allow list satisfies it.
func TestUDPRequireAllowRefusesWithoutAList(t *testing.T) {
	up := newUDPEcho(t, 0, "")
	m := New(discardLogger())
	defer m.Close()
	log := &eventLog{}
	m.SetEventSink(log.sink())

	listen := freeUDPPort(t)
	u := applyUDP(t, m, "plex", Config{Port: listen, Upstream: up.addr(), RequireAllow: true})
	client := udpClient(t, listen)
	sendUDP(t, client, "hi")
	expectNoReply(t, client, "a session without an allow list")
	waitFor(t, "the refusal", func() bool { return u.blocked.Load() == 1 })
	events := log.all()
	if len(events) != 1 || events[0].Kind != "stream-allow" || !strings.Contains(events[0].Detail, "allow list") {
		t.Fatalf("events = %+v, want one stream-allow refusal naming the allow list", events)
	}

	// A named whitelist is an allow list for this purpose.
	m.SetLists([]List{{ID: 3, Name: "friends", Prefixes: []string{"127.0.0.1/32"}}})
	if err := m.Apply("plex", Config{Enabled: true, Protocol: "udp", ListenIP: "127.0.0.1", Port: listen,
		Upstream: up.addr(), RequireAllow: true, ListIDs: []int64{3}}); err != nil {
		t.Fatal(err)
	}
	viaList := udpClient(t, listen)
	sendUDP(t, viaList, "hi")
	expectReply(t, viaList, "hi")

	// So is the card's own allow list.
	if err := m.Apply("plex", Config{Enabled: true, Protocol: "udp", ListenIP: "127.0.0.1", Port: listen,
		Upstream: up.addr(), RequireAllow: true, Allow: []string{"127.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	viaAllow := udpClient(t, listen)
	sendUDP(t, viaAllow, "hi")
	expectReply(t, viaAllow, "hi")
}

// One address may open newSessionBurst sessions at once and newSessionRate per
// second after that; an existing session keeps flowing either way.
func TestUDPNewSessionRateLimit(t *testing.T) {
	up := newUDPEcho(t, 0, "")
	m := New(discardLogger())
	defer m.Close()
	log := &eventLog{}
	m.SetEventSink(log.sink())
	var clockMu sync.Mutex
	clock := time.Now()
	m.now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return clock
	}

	listen := freeUDPPort(t)
	u := applyUDP(t, m, "plex", Config{Port: listen, Upstream: up.addr(), MaxConns: 128, MaxPerSource: 128})

	// A new socket is a new source port, so each one opens a session.
	open := func() bool {
		t.Helper()
		c := udpClient(t, listen)
		sendUDP(t, c, "hi")
		_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		_, err := c.Read(make([]byte, 8))
		_ = c.SetReadDeadline(time.Time{})
		return err == nil
	}

	var last *net.UDPConn
	for i := 0; i < newSessionBurst; i++ {
		last = udpClient(t, listen)
		sendUDP(t, last, "hi")
		expectReply(t, last, "hi")
	}
	if open() {
		t.Fatal("a session past the burst was allowed")
	}
	waitFor(t, "the rate refusal", func() bool { return u.blocked.Load() == 1 })
	events := log.all()
	if len(events) != 1 || events[0].Kind != "stream-cap" || !strings.Contains(events[0].Detail, "new sessions") {
		t.Fatalf("events = %+v, want one stream-cap refusal naming the new-session limit", events)
	}

	// The open session is unaffected: the limit is on opening, not on packets.
	sendUDP(t, last, "again")
	expectReply(t, last, "again")

	// A second refills the bucket for another newSessionRate opens.
	clockMu.Lock()
	clock = clock.Add(time.Second)
	clockMu.Unlock()
	for i := 0; i < newSessionRate; i++ {
		if !open() {
			t.Fatalf("session %d after a second was refused", i+1)
		}
	}
	if open() {
		t.Fatal("a session past the refill was allowed")
	}
}
