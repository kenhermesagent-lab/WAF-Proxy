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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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
