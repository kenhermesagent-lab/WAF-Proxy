package ha

import "testing"

func TestMakeStandaloneTurnsALeftoverStandbyIntoASingleNode(t *testing.T) {
	dir := t.TempDir()
	if err := Save(dir, &Node{NodeID: "node-a", Role: RoleStandby, State: StateStandby, Epoch: 7, Reason: "parked"}); err != nil {
		t.Fatal(err)
	}
	node, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := MakeStandalone(dir, node)
	if err != nil {
		t.Fatal(err)
	}
	if got.Role != RoleStandalone || got.State != StateStandalone || got.Reason != "" {
		t.Fatalf("standby became %+v", got)
	}
	if got.Epoch != 7 {
		t.Fatalf("epoch dropped to %d", got.Epoch)
	}
	saved, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !saved.Active() || saved.Role != RoleStandalone {
		t.Fatalf("saved role %+v is not a single node", saved)
	}

	active := &Node{NodeID: "node-a", Role: RoleActive, State: StateActive, Epoch: 9}
	same, err := MakeStandalone(dir, active)
	if err != nil {
		t.Fatal(err)
	}
	if same.Role != RoleActive || same.Epoch != 9 {
		t.Fatalf("active node changed to %+v", same)
	}
}

// A data directory that has never held a role file has no node id either, and
// Save refuses one without. A fresh single node still has to come up serving:
// with the save refused it stayed a standby that held the service address and
// never accepted a connection.
func TestMakeStandaloneMintsANodeIDOnAFreshDataDirectory(t *testing.T) {
	dir := t.TempDir()
	node, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := MakeStandalone(dir, node)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Active() || got.Role != RoleStandalone {
		t.Fatalf("a fresh node became %+v", got)
	}
	if got.NodeID == "" {
		t.Fatal("the normalised node has no id")
	}
	saved, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if saved.NodeID != got.NodeID || !saved.Active() {
		t.Fatalf("saved role %+v is not the single node that was written", saved)
	}
	// The id is stable, so a restart does not look like a different node.
	again, err := MakeStandalone(dir, saved)
	if err != nil {
		t.Fatal(err)
	}
	if again.NodeID != got.NodeID {
		t.Fatalf("node id changed from %q to %q", got.NodeID, again.NodeID)
	}
}
