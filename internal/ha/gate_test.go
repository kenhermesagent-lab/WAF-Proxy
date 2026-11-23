package ha

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestGateBlocksStandby(t *testing.T) {
	g := NewGate(false)
	var ran atomic.Int32
	if g.Go(func() { ran.Add(1) }) {
		t.Fatal("Go reported starting on a closed gate")
	}
	if g.Do(func() { ran.Add(1) }) {
		t.Fatal("Do reported running on a closed gate")
	}
	time.Sleep(20 * time.Millisecond)
	if got := ran.Load(); got != 0 {
		t.Fatalf("%d goroutines ran on a standby", got)
	}
	g.SetActive(true)
	if !g.Go(func() { ran.Add(1) }) {
		t.Fatal("Go refused an open gate")
	}
	deadline := time.Now().Add(time.Second)
	for ran.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := ran.Load(); got != 1 {
		t.Fatalf("ran %d times, want 1", got)
	}
}

func TestGateDefaultsClosedOnZeroValue(t *testing.T) {
	var g Gate
	if g.Active() {
		t.Fatal("a zero gate is active")
	}
}
