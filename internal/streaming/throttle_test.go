package streaming

import (
	"net/netip"
	"testing"
	"time"
)

func TestThrottleStaysBounded(t *testing.T) {
	th := newThrottle(time.Minute)
	now := time.Now()
	for i := 0; i < throttleMax*2; i++ {
		addr := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		if emit, _ := th.allow("plex", addr, now); !emit {
			t.Fatalf("first refusal for %s was suppressed", addr)
		}
	}
	if len(th.seen) > throttleMax {
		t.Fatalf("refusal table grew past its bound: %d entries", len(th.seen))
	}
}

func TestThrottleSuppressesRepeats(t *testing.T) {
	th := newThrottle(time.Minute)
	now := time.Now()
	addr := netip.MustParseAddr("203.0.113.7")
	if emit, _ := th.allow("plex", addr, now); !emit {
		t.Fatal("first refusal was suppressed")
	}
	for i := 0; i < 3; i++ {
		if emit, _ := th.allow("plex", addr, now.Add(time.Second)); emit {
			t.Fatal("repeat refusal inside the window was emitted")
		}
	}
	emit, suppressed := th.allow("plex", addr, now.Add(2*time.Minute))
	if !emit || suppressed != 3 {
		t.Fatalf("window summary = (%v, %d), want (true, 3)", emit, suppressed)
	}
}
