package ha

import (
	"context"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func testSecret(seed byte) []byte {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = seed + byte(i)
	}
	return secret
}

func TestSnapshotEnvelopeRoundTrip(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Unscoped().SetSetting("ha.snapshot", "one"); err != nil {
		t.Fatal(err)
	}
	snap, err := st.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	secret := testSecret(1)
	raw, err := SealSnapshot(secret, "cluster-1", snap)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenSnapshot(secret, "cluster-1", raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tables["settings"].Rows == nil || got.SchemaVersion != store.SchemaVersion() {
		t.Fatalf("opened snapshot = %+v", got)
	}
	if _, err := OpenSnapshot(testSecret(2), "cluster-1", raw); err == nil {
		t.Fatal("the snapshot opened under another secret")
	}
	if _, err := OpenSnapshot(secret, "cluster-2", raw); err == nil {
		t.Fatal("the snapshot opened under another cluster")
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)/2] ^= 0x40
	if _, err := OpenSnapshot(secret, "cluster-1", tampered); err == nil {
		t.Fatal("a tampered snapshot opened")
	}
}

func TestPullAppliesPeerSnapshot(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	stA, err := store.Open(dirA)
	if err != nil {
		t.Fatal(err)
	}
	defer stA.Close()
	stB, err := store.Open(dirB)
	if err != nil {
		t.Fatal(err)
	}
	defer stB.Close()
	if err := stA.Unscoped().SetSetting("ha.pulled", "yes"); err != nil {
		t.Fatal(err)
	}

	idA, addr := startJoinServer(t, dirA, nil, stA)
	code, err := WritePairingCode(dirA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Join(context.Background(), dirB, addr, Fingerprint(idA.Leaf), code); err != nil {
		t.Fatal(err)
	}
	snap, err := Pull(context.Background(), dirB, stB)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snap.Tables["settings"]; !ok {
		t.Fatal("pulled snapshot has no settings table")
	}
	got, err := stB.Unscoped().GetSetting("ha.pulled")
	if err != nil || got != "yes" {
		t.Fatalf("pulled setting = %q, %v", got, err)
	}
}
