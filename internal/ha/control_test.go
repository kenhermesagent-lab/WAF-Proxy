package ha

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestServeControlRefusesALiveSocket(t *testing.T) {
	dir := t.TempDir()
	sock := ControlSocketPath(dir)
	m := NewManager(dir, Hooks{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := ServeControl(ctx, sock, m, discardLog())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	if _, err := ServeControl(context.Background(), sock, m, discardLog()); err == nil ||
		!strings.Contains(err.Error(), "already in use") {
		t.Fatalf("second bind = %v, want an in-use error", err)
	}
	// The live listener must still own the path and answer moves.
	reply, err := Control(context.Background(), sock, ControlRequest{Command: "status"})
	if err != nil || !reply.OK {
		t.Fatalf("status after refused bind = %+v, %v", reply, err)
	}
}

func TestServeControlReplacesAStaleSocket(t *testing.T) {
	dir := t.TempDir()
	sock := ControlSocketPath(dir)
	if err := os.MkdirAll(RoleDir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	stale, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	_ = stale.Close() // the path stays behind without a listener

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := ServeControl(ctx, sock, NewManager(dir, Hooks{}), discardLog())
	if err != nil {
		t.Fatalf("stale socket was not replaced: %v", err)
	}
	defer ln.Close()
	reply, err := Control(context.Background(), sock, ControlRequest{Command: "status"})
	if err != nil || !reply.OK {
		t.Fatalf("status on the replacement socket = %+v, %v", reply, err)
	}
}

func TestServeControlCleanupLeavesThePathForTheNextOwner(t *testing.T) {
	dir := t.TempDir()
	sock := ControlSocketPath(dir)
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := ServeControl(ctx, sock, NewManager(dir, Hooks{}), discardLog()); err != nil {
		t.Fatal(err)
	}
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Lstat(sock); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cancelled control socket was not removed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	next, err := ServeControl(context.Background(), sock, NewManager(dir, Hooks{}), discardLog())
	if err != nil {
		t.Fatalf("the next owner could not bind: %v", err)
	}
	_ = next.Close()
}
