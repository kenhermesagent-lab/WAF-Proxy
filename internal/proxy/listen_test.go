package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"
)

func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd on this platform")
	}
	return len(entries)
}

// A node that fails over and back binds the same service address repeatedly
// without leaking sockets or goroutines.
func TestListenRebindsTheSameAddress(t *testing.T) {
	px, err := New(Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	addr := freeAddr(t)
	before := openFDs(t)

	for i := 0; i < 100; i++ {
		lns, err := px.Listen(context.Background(), addr)
		if err != nil {
			t.Fatalf("cycle %d: listen: %v", i, err)
		}
		if got := lns.Addrs(); len(got) != 1 || got[0] != addr {
			t.Fatalf("cycle %d: addrs = %v, want %s", i, got, addr)
		}
		if err := waitDial(addr); err != nil {
			t.Fatalf("cycle %d: not accepting: %v", i, err)
		}
		lns.Close()
	}

	deadline := time.Now().Add(2 * time.Second)
	for openFDs(t) > before+5 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if after := openFDs(t); after > before+5 {
		t.Fatalf("file descriptors grew from %d to %d over 100 bind/close cycles", before, after)
	}
}

func TestListenDrainReleasesThePort(t *testing.T) {
	px, err := New(Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	addr := freeAddr(t)
	lns, err := px.Listen(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- lns.Serve() }()
	if err := waitDial(addr); err != nil {
		t.Fatal(err)
	}
	lns.DrainTimeout(time.Second)
	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after Drain")
	}
	if px.Ready() {
		t.Fatal("a drained server still reports ready")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("port not released after Drain: %v", err)
	}
	_ = ln.Close()
	px.SetDraining(false)
	if !px.Ready() {
		t.Fatal("promotion did not clear the drain flag")
	}
}
