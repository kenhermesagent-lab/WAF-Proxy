package ha

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestFencerExitZeroMeansThePeerIsDown(t *testing.T) {
	if err := (Fencer{Command: "true"}).Run(context.Background()); err != nil {
		t.Fatalf("exit 0 was treated as a failure: %v", err)
	}
}

func TestFencerNonZeroBlocks(t *testing.T) {
	err := Fencer{Command: "exit 1"}.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "fence command failed") {
		t.Fatalf("exit 1 = %v", err)
	}
}

func TestFencerTimesOut(t *testing.T) {
	started := time.Now()
	err := Fencer{Command: "sleep 5", Timeout: 100 * time.Millisecond}.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout = %v", err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatalf("the timeout was not enforced: %s", time.Since(started))
	}
}

func TestFencerSubstitutesThePeerAsOneWord(t *testing.T) {
	if err := (Fencer{Command: `test {peer} = '10.0.0.11'`, Peer: "10.0.0.11"}).Run(context.Background()); err != nil {
		t.Fatalf("substitution: %v", err)
	}
	// A peer string with shell syntax must stay one argument: the test fails,
	// the injected exit 7 never runs.
	err := Fencer{Command: `test {peer} = '10.0.0.11'`, Peer: "10.0.0.11'; exit 7 #"}.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exit status 1") {
		t.Fatalf("injected peer = %v", err)
	}
}

func TestFencerWithoutACommandBlocks(t *testing.T) {
	if err := (Fencer{}).Run(context.Background()); err == nil {
		t.Fatal("an empty fence command passed")
	}
}
