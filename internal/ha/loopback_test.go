package ha

import (
	"context"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// TestOldActiveFollowsTheNewActive walks a whole move over the real link on
// loopback: B is promoted out of standby, A steps down, and A must then apply
// what B writes. This is the P5-05/P5-06 direction that unit hooks cannot
// prove, because it needs two live join servers and two stores.
func TestOldActiveFollowsTheNewActive(t *testing.T) {
	ctx := context.Background()
	dirA, dirB := t.TempDir(), t.TempDir()
	key := []byte("0123456789abcdef0123456789abcdef")
	stA, err := store.Open(dirA)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stA.Close() })
	stB, err := store.Open(dirB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stB.Close() })
	stA.SetSessionKey(key)
	stB.SetSessionKey(key)
	userID, err := stA.CreateUser("admin", "hash", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stB.CreateUser("admin", "hash", "", "", false); err != nil {
		t.Fatal(err)
	}

	// A is the active and answers its own quiesce requests.
	quiesced := NewQuiesce()
	idA, addrA, _ := startJoinServerFull(t, dirA, nil, stA, quiesced)
	code, err := WritePairingCode(dirA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Join(ctx, dirB, addrA, Fingerprint(idA.Leaf), code); err != nil {
		t.Fatal(err)
	}
	idB, addrB, _ := startJoinServerFull(t, dirB, nil, stB, nil)

	// A's pair is what its follower dials after the move, so point it at B.
	pairA, err := LoadPair(dirA)
	if err != nil || pairA == nil {
		t.Fatalf("A pair = %+v, %v", pairA, err)
	}
	pairA.PeerAddr = addrB
	pairA.PeerFingerprint = Fingerprint(idB.Leaf)
	if err := SavePair(dirA, pairA); err != nil {
		t.Fatal(err)
	}

	if err := Save(dirA, &Node{NodeID: idA.Node, Role: RoleActive, Epoch: 9}); err != nil {
		t.Fatal(err)
	}
	if err := Save(dirB, &Node{NodeID: idB.Node, Role: RoleStandby, Epoch: 9}); err != nil {
		t.Fatal(err)
	}
	stA.SetNodeID(idA.Node)
	if _, err := SyncSnapshotOnce(ctx, dirB, stB); err != nil {
		t.Fatal(err)
	}

	served := false
	_, err = Promote(ctx, dirB, Hooks{
		Preflight: func(ctx context.Context) (PreflightInput, error) {
			return GatherPreflight(ctx, PreflightSource{DataDir: dirB, Store: stB})
		},
		QuiescePeer: func(ctx context.Context) error { return SetPeerQuiesced(ctx, dirB, true) },
		ResumePeer:  func(ctx context.Context) error { return SetPeerQuiesced(ctx, dirB, false) },
		Drain:       func(ctx context.Context) error { return Drain(ctx, dirB, stB, 5*time.Second) },
		Serve: func(context.Context) error {
			stB.SetNodeID(idB.Node)
			stB.SetAuditEnabled(true)
			served = true
			return nil
		},
	}, false, false)
	if err != nil {
		t.Fatalf("promote B: %v", err)
	}
	if !quiesced.Active() {
		t.Fatal("B did not quiesce A's configuration writes")
	}

	demoted := false
	if _, err := Demote(ctx, dirA, Hooks{DemotePlane: func(context.Context) {
		stA.SetNodeID("")
		stA.SetAuditEnabled(false)
		demoted = true
	}}); err != nil {
		t.Fatalf("demote A: %v", err)
	}
	if node, _ := Load(dirA); node.Role != RoleStandby || node.Epoch != 9 {
		t.Fatalf("A after stepping down = %+v", node)
	}

	// B writes under its new epoch; A must receive it through B's stream.
	if err := stB.CreateSession("cookie-b", userID, "csrf-b", "198.51.100.7", "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	res, err := SyncOnce(ctx, dirA, stA)
	if err != nil {
		t.Fatalf("A follows B: %v", err)
	}
	if res.Snapshot {
		t.Fatal("A fell back to a snapshot instead of following B's stream")
	}
	if res.Applied == 0 {
		t.Fatalf("A applied nothing: %+v", res)
	}
	if _, err := stA.LookupSession("cookie-b"); err != nil {
		t.Fatalf("A cannot resolve the session B minted: %v", err)
	}

	// The reverse direction still works from the same follower: B deletes, A
	// removes.
	if err := stB.DeleteSession("cookie-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := SyncOnce(ctx, dirA, stA); err != nil {
		t.Fatal(err)
	}
	if _, err := stA.LookupSession("cookie-b"); err == nil {
		t.Fatal("B's logout never reached A")
	}

	if !served || !demoted {
		t.Fatalf("served=%v demoted=%v", served, demoted)
	}
	if node, _ := Load(dirB); node.Role != RoleActive || node.Epoch != 10 {
		t.Fatalf("B after promotion = %+v", node)
	}
	if err := SetPeerQuiesced(ctx, dirB, false); err != nil {
		t.Fatal(err)
	}
	if quiesced.Active() {
		t.Fatal("resuming writes on A did not clear the gate")
	}
}
