package plex

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
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

func TestForwarderRelaysAndCounts(t *testing.T) {
	upstream := echoServer(t)
	defer upstream.Close()
	m := New(discardLogger())
	defer m.Close()

	port := freePort(t)
	if err := m.Apply(Config{Enabled: true, ListenIP: "127.0.0.1", Port: port, Upstream: upstream.Addr().String()}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if st := m.Status(); !st.Bound || st.ListenAddr == "" {
		t.Fatalf("status = %+v, want a bound listener", st)
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("plex-bytes")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("plex-bytes"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "plex-bytes" {
		t.Fatalf("echo = %q", buf)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m.Status().Total == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("total counter = %d, want 1", m.Status().Total)
}

func TestForwarderAllowListBlocks(t *testing.T) {
	upstream := echoServer(t)
	defer upstream.Close()
	m := New(discardLogger())
	defer m.Close()

	port := freePort(t)
	// 127.0.0.1 is not inside the allowed network, so every connection is
	// closed before it can reach Plex.
	if err := m.Apply(Config{Enabled: true, ListenIP: "127.0.0.1", Port: port,
		Upstream: upstream.Addr().String(), Allow: []string{"198.51.100.0/24"}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection was not closed by the allow list")
	}
	if st := m.Status(); st.Blocked != 1 || st.Total != 0 {
		t.Fatalf("status = %+v, want one blocked and no accepted connections", st)
	}
}

func TestForwarderRefusesBannedSources(t *testing.T) {
	upstream := echoServer(t)
	defer upstream.Close()
	m := New(discardLogger())
	defer m.Close()

	banned := netip.MustParseAddr("127.0.0.1")
	m.SetBans(func(addr netip.Addr) bool { return addr == banned })

	port := freePort(t)
	if err := m.Apply(Config{Enabled: true, ListenIP: "127.0.0.1", Port: port, Upstream: upstream.Addr().String()}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a banned source was not refused")
	}
	if st := m.Status(); st.Banned != 1 || st.Total != 0 {
		t.Fatalf("status = %+v, want one ban refusal and no accepted connection", st)
	}

	// Lifting the ban lets the same address through again.
	m.SetBans(func(netip.Addr) bool { return false })
	conn2, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial after unban: %v", err)
	}
	defer conn2.Close()
	_ = conn2.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn2.Write([]byte("still-here")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("still-here"))
	if _, err := io.ReadFull(conn2, buf); err != nil {
		t.Fatalf("read after unban: %v", err)
	}
	if string(buf) != "still-here" {
		t.Fatalf("echo = %q", buf)
	}
}

func TestForwarderDisableStopsListener(t *testing.T) {
	m := New(discardLogger())
	defer m.Close()
	port := freePort(t)
	base := Config{ListenIP: "127.0.0.1", Port: port, Upstream: "127.0.0.1:32400"}

	if err := m.Apply(withEnabled(base, true)); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := m.Apply(withEnabled(base, false)); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if st := m.Status(); st.Bound {
		t.Fatalf("status = %+v, want a stopped forwarder", st)
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("listener still accepting after disable")
	}
}

func withEnabled(c Config, enabled bool) Config {
	c.Enabled = enabled
	return c
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		name    string
		in      Config
		want    Config
		wantErr bool
	}{
		{
			name: "defaults port and upstream port",
			in:   Config{Upstream: "192.168.101.10"},
			want: Config{Port: 32400, Upstream: "192.168.101.10:32400", MaxConns: DefaultMaxConns},
		},
		{
			name: "strips scheme",
			in:   Config{Upstream: "http://192.168.101.10:32400/"},
			want: Config{Port: 32400, Upstream: "192.168.101.10:32400", MaxConns: DefaultMaxConns},
		},
		{
			name: "normalises allow entries",
			in:   Config{Upstream: "plex.lan:32400", Allow: []string{"192.168.101.10", "10.0.0.0/8"}},
			want: Config{Port: 32400, Upstream: "plex.lan:32400", MaxConns: DefaultMaxConns,
				Allow: []string{"192.168.101.10/32", "10.0.0.0/8"}},
		},
		{name: "missing upstream", in: Config{}, wantErr: true},
		{name: "pasted sentence", in: Config{Upstream: "not a url"}, wantErr: true},
		{name: "url with empty host", in: Config{Upstream: "http://"}, wantErr: true},
		{name: "bad port", in: Config{Upstream: "plex.lan", Port: 70000}, wantErr: true},
		{name: "bad allow entry", in: Config{Upstream: "plex.lan", Allow: []string{"not-an-ip"}}, wantErr: true},
	}
	for _, c := range cases {
		got, err := c.in.Normalize()
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
		if len(c.want.Allow) > 0 {
			if fmt.Sprint(got.Allow) != fmt.Sprint(c.want.Allow) {
				t.Errorf("%s: allow = %v, want %v", c.name, got.Allow, c.want.Allow)
			}
		}
	}
}
