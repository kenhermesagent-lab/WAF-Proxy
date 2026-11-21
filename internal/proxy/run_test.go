package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestRunBindsPrimaryAndExtraListeners(t *testing.T) {
	px, err := New(Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	primary, extra := freeAddr(t), freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- px.Run(ctx, primary, extra) }()

	for _, addr := range []string{primary, extra} {
		var conn net.Conn
		var err error
		for i := 0; i < 50; i++ {
			if conn, err = net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
				_ = conn.Close()
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("listener %s did not open: %v", addr, err)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
}

func TestRunRecordsOptionalListenerFailure(t *testing.T) {
	px, err := New(Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	primary := freeAddr(t)
	bad := "this-is-not-a-listen-address"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- px.Run(ctx, primary, bad) }()

	if err := waitDial(primary); err != nil {
		t.Fatalf("primary listener did not open: %v", err)
	}
	if got := px.ListenerError(bad); got == "" {
		t.Fatal("optional listener failure was not recorded")
	}
	cancel()
	<-done
}

// The dashboard separates proxy traffic from the host's other WAN traffic, so
// the listener must count the bytes it accepts, handshake attempts included.
func TestRunCountsProxyListenerBytes(t *testing.T) {
	met := metrics.New("", "")
	px, err := New(Deps{Metrics: met, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- px.Run(ctx, addr) }()
	defer func() {
		cancel()
		<-done
	}()

	if err := waitDial(addr); err != nil {
		t.Fatalf("listener did not open: %v", err)
	}
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(make([]byte, 512)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = conn.Read(make([]byte, 64))

	// The write direction is covered by TestCountingConnCountsBothDirections; a
	// rejected handshake may close without writing, so only inbound is asserted.
	// The server reads the bytes after the client's own read returns, so poll.
	var in uint64
	for i := 0; i < 100; i++ {
		if in, _ = met.ProxyBytes(); in >= 512 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if in < 512 {
		t.Fatalf("proxy inbound = %d, want at least the 512 bytes sent", in)
	}
}

func waitDial(addr string) error {
	var err error
	for i := 0; i < 50; i++ {
		var conn net.Conn
		if conn, err = net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return err
}
