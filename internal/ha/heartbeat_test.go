package ha

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMonitorActsOnTheThirdLostBeat(t *testing.T) {
	fail := true
	var changes []bool
	m := NewMonitor(func(context.Context) error {
		if fail {
			return errors.New("no answer")
		}
		return nil
	})
	m.Now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	m.OnChange = func(h Health) { changes = append(changes, h.Reachable) }

	for i := 1; i <= 2; i++ {
		if !m.Beat(context.Background()) {
			t.Fatalf("beat %d treated the peer as down", i)
		}
	}
	if h := m.Health(); h.Failures != 2 {
		t.Fatalf("after two beats: %+v", h)
	}
	if m.Beat(context.Background()) {
		t.Fatal("the third lost beat did not trip the monitor")
	}
	if h := m.Health(); h.Reachable || h.Failures != 3 {
		t.Fatalf("after three beats: %+v", h)
	}
	// Another failure must not fire a second transition.
	if m.Beat(context.Background()) {
		t.Fatal("a fourth lost beat reported reachable")
	}
	fail = false
	if !m.Beat(context.Background()) {
		t.Fatal("recovery did not reset the count")
	}
	if h := m.Health(); !h.Reachable || h.Failures != 0 {
		t.Fatalf("after recovery: %+v", h)
	}
	want := []bool{false, true}
	if len(changes) != len(want) || changes[0] != want[0] || changes[1] != want[1] {
		t.Fatalf("changes = %v, want %v", changes, want)
	}
}

func TestPingPeerReportsTheRole(t *testing.T) {
	dirA, dirB, _, _, idA, _ := pairForTest(t)
	if err := Save(dirA, &Node{NodeID: idA.Node, Role: RoleActive, Epoch: 11}); err != nil {
		t.Fatal(err)
	}
	ping, err := PingPeer(context.Background(), dirB)
	if err != nil {
		t.Fatal(err)
	}
	if ping.Role != RoleActive || ping.Epoch != 11 || ping.State != StateActive || ping.Node != idA.Node || !ping.OK {
		t.Fatalf("ping = %+v", ping)
	}
	// The upgrade check reads these, so the heartbeat has to carry them.
	if ping.Version == "" || ping.Schema == "" || ping.Protocol != ProtocolVersion {
		t.Fatalf("ping lacks release facts: %+v", ping)
	}
}
