package ha

import (
	"context"
	"testing"
)

func TestSelfDemoteStaysSplitBrainRisk(t *testing.T) {
	dir := t.TempDir()
	roleFor(t, dir, RoleActive, 9)
	demoted, started := false, false
	res, err := SelfDemote(context.Background(), dir, Hooks{
		DemotePlane:      func(context.Context) { demoted = true },
		StartReplication: func() { started = true },
	})
	if err != nil {
		t.Fatal(err)
	}
	node, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if node.Role != RoleStandby || node.EffectiveState() != StateSplitBrainRisk {
		t.Fatalf("role after self-demotion = %+v", node)
	}
	if Serving(node.EffectiveState()) {
		t.Fatal("a split-brain-risk node reported serving")
	}
	if started {
		t.Fatal("a split-brain-risk node started following the peer")
	}
	if !demoted || res.Epoch != 9 {
		t.Fatalf("demoted=%v epoch=%d", demoted, res.Epoch)
	}
}

func TestReconcileAdoptsThePeerEpoch(t *testing.T) {
	dir := t.TempDir()
	roleFor(t, dir, RoleStandby, 9)
	node, _ := Load(dir)
	if _, err := EnterState(dir, node, StateSplitBrainRisk); err != nil {
		t.Fatal(err)
	}
	node, _ = Load(dir)
	out, err := Reconcile(dir, node, 11)
	if err != nil {
		t.Fatal(err)
	}
	if out.State != StateStandby || out.Epoch != 11 || out.Reason != "" {
		t.Fatalf("reconciled node = %+v", out)
	}
	if _, err := Reconcile(dir, out, 12); err == nil {
		t.Fatal("reconciled a node that was not split-brain-risk")
	}
}

func TestParkPersistsTheReason(t *testing.T) {
	dir := t.TempDir()
	roleFor(t, dir, RoleStandby, 4)
	node, _ := Load(dir)
	if _, err := Park(dir, node, "4 automatic moves in 1h"); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.EffectiveState() != StateParked || loaded.Reason == "" {
		t.Fatalf("parked node = %+v", loaded)
	}
	if Serving(loaded.EffectiveState()) {
		t.Fatal("a parked node reported serving")
	}
	if _, err := Park(dir, &Node{NodeID: "n", Role: RoleActive, Epoch: 1}, "x"); err == nil {
		t.Fatal("parked an active node")
	}
}
