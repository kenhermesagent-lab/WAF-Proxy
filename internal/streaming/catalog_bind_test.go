package streaming

import (
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"
)

// presetFreeRange finds count consecutive loopback ports free for every
// protocol the preset binds, so one card's range never lands on another's.
func presetFreeRange(t *testing.T, count int, wantTCP, wantUDP bool) int {
	t.Helper()
	for attempt := 0; attempt < 300; attempt++ {
		base := freePort(t)
		if base+count-1 > 65535 {
			continue
		}
		var held []io.Closer
		ok := true
		for i := 0; i < count && ok; i++ {
			port := base + i
			if wantTCP {
				ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
				if err != nil {
					ok = false
					break
				}
				held = append(held, ln)
			}
			if wantUDP {
				pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
				if err != nil {
					ok = false
					break
				}
				held = append(held, pc)
			}
		}
		for _, c := range held {
			_ = c.Close()
		}
		if ok {
			return base
		}
	}
	t.Fatalf("no run of %d free ports for tcp=%v udp=%v", count, wantTCP, wantUDP)
	return 0
}

// presetEchoTCP answers on every accepted connection, so a relayed stream has a
// peer to talk to.
func presetEchoTCP(t *testing.T, port int) {
	t.Helper()
	ln := echoServerAt(t, port)
	t.Cleanup(func() { _ = ln.Close() })
}

// presetEchoUDP echoes one datagram back to its sender.
func presetEchoUDP(t *testing.T, port int) {
	t.Helper()
	pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("upstream udp %d: %v", port, err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
}

// Every preset must open its listener and move bytes, not just validate: the
// page promises that enabling a card reaches the server behind it.
func TestEveryPresetListensAndRelays(t *testing.T) {
	for _, def := range Catalog {
		def := def
		t.Run(def.ID, func(t *testing.T) {
			t.Parallel()
			needsTCP := def.Protocol != "udp"
			needsUDP := def.Protocol != "tcp"
			count := def.PortCount
			port := presetFreeRange(t, count, needsTCP, needsUDP)
			upstream := presetFreeRange(t, count, needsTCP, needsUDP)
			for i := 0; i < count; i++ {
				if needsTCP {
					presetEchoTCP(t, upstream+i)
				}
				if needsUDP {
					presetEchoUDP(t, upstream+i)
				}
			}

			m := New(slog.New(slog.NewTextHandler(io.Discard, nil)))
			t.Cleanup(m.Close)
			if err := m.Apply(def.ID, Config{
				Enabled:   true,
				ListenIP:  "127.0.0.1",
				Protocol:  def.Protocol,
				Port:      port,
				PortCount: count,
				Upstream:  net.JoinHostPort("127.0.0.1", strconv.Itoa(upstream)),
			}); err != nil {
				t.Fatalf("apply: %v", err)
			}

			status := statusOf(t, m, def.ID)
			if !status.Bound {
				t.Fatalf("%s is enabled but not bound: %+v", def.ID, status)
			}
			if status.ListenAddr == "" {
				t.Fatalf("%s reports no listen address", def.ID)
			}

			for i := 0; i < count; i++ {
				if needsTCP {
					checkTCPRelay(t, port+i)
				}
				if needsUDP {
					checkUDPRelay(t, port+i)
				}
			}
			// The counts land after the streams close, so read them once the
			// relay goroutines have finished.
			waitFor(t, "the relayed streams to be counted", func() bool {
				return statusOf(t, m, def.ID).Total >= uint64(count)
			})
		})
	}
}

func statusOf(t *testing.T, m *Manager, id string) Status {
	t.Helper()
	for _, st := range m.Statuses() {
		if st.ID == id {
			return st
		}
	}
	t.Fatalf("no status for %s", id)
	return Status{}
}

func checkTCPRelay(t *testing.T, port int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		t.Fatalf("dial %d: %v", port, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write %d: %v", port, err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read %d: %v", port, err)
	}
	if string(buf) != "ping" {
		t.Fatalf("relay on %d returned %q", port, buf)
	}
}

func checkUDPRelay(t *testing.T, port int) {
	t.Helper()
	conn, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial udp %d: %v", port, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write udp %d: %v", port, err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read udp %d: %v", port, err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("udp relay on %d returned %q", port, buf[:n])
	}
}
