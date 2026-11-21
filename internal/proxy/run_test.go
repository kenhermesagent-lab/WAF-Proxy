package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
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
