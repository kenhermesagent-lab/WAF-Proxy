package netbind

import (
	"errors"
	"runtime"
	"syscall"
	"testing"
)

func TestListenBindsForeignAddress(t *testing.T) {
	if runtime.GOOS != "linux" {
		if _, err := Listen("tcp4", "192.0.2.10:0"); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("non-Linux Listen = %v, want ErrUnsupported", err)
		}
		return
	}
	ln, err := Listen("tcp4", "192.0.2.10:0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("IP_FREEBIND needs a capability this process does not have: %v", err)
		}
		t.Fatalf("freebind listen: %v", err)
	}
	defer ln.Close()
	if got := ln.Addr().String(); got == "" {
		t.Fatal("listener has no address")
	}
}
