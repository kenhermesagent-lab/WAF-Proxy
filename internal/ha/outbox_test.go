package ha

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// pairForTest starts an active node, pairs a second node with it, and returns
// both stores and the active identity. The session key stands in for the
// cluster master key that pairing would transfer.
func pairForTest(t *testing.T) (dirA, dirB string, stA, stB *store.Store, idA *Identity, userID int64) {
	t.Helper()
	dirA, dirB = t.TempDir(), t.TempDir()
	var err error
	stA, err = store.Open(dirA)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stA.Close() })
	stB, err = store.Open(dirB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stB.Close() })
	key := []byte("0123456789abcdef0123456789abcdef")
	stA.SetSessionKey(key)
	stB.SetSessionKey(key)
	userID, err = stA.CreateUser("admin", "hash", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stB.CreateUser("admin", "hash", "", "", false); err != nil {
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
	stA.SetNodeID(idA.Node)
	return dirA, dirB, stA, stB, idA, userID
}

func TestOutboxStreamsSessionsToTheStandby(t *testing.T) {
	_, dirB, stA, stB, _, userID := pairForTest(t)
	if err := stA.CreateSession("cookie-token", userID, "csrf", "127.0.0.1", "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	res, err := SyncOnce(context.Background(), dirB, stB)
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied != 1 || res.Snapshot || res.AckedSeq == 0 {
		t.Fatalf("first sync = %+v", res)
	}
	if _, err := stB.LookupSession("cookie-token"); err != nil {
		t.Fatalf("the standby cannot resolve a session minted on the active: %v", err)
	}
	// The active prunes what the standby acknowledged, so the stream only holds
	// changes that are still needed.
	stats, err := stA.OutboxStats()
	if err != nil || stats.Depth != 0 {
		t.Fatalf("active outbox after ack = %+v, %v", stats, err)
	}
	if err := stA.DeleteSession("cookie-token"); err != nil {
		t.Fatal(err)
	}
	if _, err := SyncOnce(context.Background(), dirB, stB); err != nil {
		t.Fatal(err)
	}
	if _, err := stB.LookupSession("cookie-token"); err == nil {
		t.Fatal("a logout on the active did not reach the standby")
	}
}

func TestOutboxBacksBansAndGateSessions(t *testing.T) {
	_, dirB, stA, stB, _, _ := pairForTest(t)
	if err := stA.AddUsernameBan("mallory", "abuse", "admin", nil); err != nil {
		t.Fatal(err)
	}
	if err := stA.CreateGateSession("visitor-token", 0, "alice", "127.0.0.1", "ua", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := SyncOnce(context.Background(), dirB, stB); err != nil {
		t.Fatal(err)
	}
	if banned, err := stB.UsernameBanned("mallory"); err != nil || !banned {
		t.Fatalf("standby username ban = %v, %v", banned, err)
	}
	if name, ok := stB.LookupGateSession("visitor-token", 0); !ok || name != "alice" {
		t.Fatalf("standby gate session = %q, %v", name, ok)
	}
	if _, err := stA.RemoveUsernameBan("mallory"); err != nil {
		t.Fatal(err)
	}
	if err := stA.DeleteGateSession("visitor-token"); err != nil {
		t.Fatal(err)
	}
	if _, err := SyncOnce(context.Background(), dirB, stB); err != nil {
		t.Fatal(err)
	}
	if banned, err := stB.UsernameBanned("mallory"); err != nil || banned {
		t.Fatalf("standby kept a lifted username ban: %v, %v", banned, err)
	}
	if _, ok := stB.LookupGateSession("visitor-token", 0); ok {
		t.Fatal("standby kept a revoked gate session")
	}
}

func TestOutboxGapFallsBackToSnapshot(t *testing.T) {
	_, dirB, stA, stB, _, userID := pairForTest(t)
	if err := stA.CreateSession("first", userID, "", "", "", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := SyncOnce(context.Background(), dirB, stB); err != nil {
		t.Fatal(err)
	}
	if err := stA.CreateSession("second", userID, "", "", "", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Drop changes the standby still needs, which is exactly what pruning an
	// acknowledged stream must never do.
	if err := stA.PruneOutbox(2); err != nil {
		t.Fatal(err)
	}
	if err := stA.CreateSession("third", userID, "", "", "", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := stA.LookupSession("third"); err != nil {
		t.Fatalf("the active does not hold the new session: %v", err)
	}
	res, err := SyncOnce(context.Background(), dirB, stB)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Snapshot {
		t.Fatalf("a pruned stream did not fall back to a snapshot: %+v", res)
	}
	if _, err := stB.LookupSession("third"); err != nil {
		t.Fatalf("the snapshot is missing a live session: %v", err)
	}
	if stats, err := stA.OutboxStats(); err != nil || stats.Depth != 0 {
		t.Fatalf("the acknowledged snapshot left %+v, %v", stats, err)
	}
}

func TestSnapshotSyncCarriesConfigurationAndNeverRollsBack(t *testing.T) {
	_, dirB, stA, stB, _, _ := pairForTest(t)
	if err := stA.Unscoped().SetSetting("ha.config", "value"); err != nil {
		t.Fatal(err)
	}
	res, err := SyncSnapshotOnce(context.Background(), dirB, stB)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Snapshot {
		t.Fatalf("the configuration snapshot was skipped: %+v", res)
	}
	if v, err := stB.Unscoped().GetSetting("ha.config"); err != nil || v != "value" {
		t.Fatalf("snapshot did not carry configuration: %q, %v", v, err)
	}
	// A copy that is ahead of the snapshot must be kept: applying an older
	// snapshot would silently drop changes the stream already delivered.
	pairB, err := LoadPair(dirB)
	if err != nil {
		t.Fatal(err)
	}
	if err := stB.AckPeer(pairB.PeerFingerprint, 999); err != nil {
		t.Fatal(err)
	}
	res, err = SyncSnapshotOnce(context.Background(), dirB, stB)
	if err != nil {
		t.Fatal(err)
	}
	if res.Snapshot {
		t.Fatalf("a snapshot older than the applied stream replaced the copy: %+v", res)
	}
}

func TestConfigVersionIgnoresStreamedState(t *testing.T) {
	_, dirB, stA, stB, _, userID := pairForTest(t)
	hashA, err := stA.ConfigHash()
	if err != nil {
		t.Fatal(err)
	}
	version, err := ConfigVersion(context.Background(), dirB)
	if err != nil {
		t.Fatal(err)
	}
	if version.Hash != hashA {
		t.Fatalf("version hash %s != active hash %s", version.Hash, hashA)
	}
	if version.Time == "" {
		t.Fatal("config version carries no peer time; preflight needs it for skew")
	}

	// A session is streamed state. It must not make the standby take a snapshot.
	if err := stA.CreateSession("cookie", userID, "csrf", "", "", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	after, err := ConfigVersion(context.Background(), dirB)
	if err != nil {
		t.Fatal(err)
	}
	if after.Hash != version.Hash {
		t.Fatalf("a session changed the published config hash: %s -> %s", version.Hash, after.Hash)
	}
	if after.OutboxSeq <= version.OutboxSeq {
		t.Fatalf("the outbox position did not advance: %d -> %d", version.OutboxSeq, after.OutboxSeq)
	}

	// A configuration edit does move it, and the snapshot reports the new hash
	// so the loop can remember what it just applied.
	if err := stA.Unscoped().SetSetting("ha.probe", "two"); err != nil {
		t.Fatal(err)
	}
	changed, err := ConfigVersion(context.Background(), dirB)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Hash == version.Hash {
		t.Fatal("a settings change did not move the config hash")
	}
	res, err := SyncSnapshotOnce(context.Background(), dirB, stB)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Snapshot || res.ConfigHash != changed.Hash {
		t.Fatalf("snapshot result = %+v, want hash %s", res, changed.Hash)
	}
	if got, err := stB.ConfigHash(); err != nil || got != changed.Hash {
		t.Fatalf("standby config hash = %s, %v; want %s", got, err, changed.Hash)
	}
}

func TestOutboxOverflowFallsBackToSnapshot(t *testing.T) {
	_, dirB, stA, stB, _, userID := pairForTest(t)
	if err := stA.CreateSession("during-overflow", userID, "", "", "", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Shrink the ceiling instead of writing a hundred megabytes: the path a
	// real overflow takes is identical.
	old := outboxLimit
	outboxLimit = 10
	t.Cleanup(func() { outboxLimit = old })
	res, err := SyncOnce(context.Background(), dirB, stB)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Snapshot {
		t.Fatalf("an outbox over the ceiling did not fall back to a snapshot: %+v", res)
	}
	if _, err := stB.LookupSession("during-overflow"); err != nil {
		t.Fatalf("a session created during an overflow did not survive: %v", err)
	}
	if stats, err := stA.OutboxStats(); err != nil || stats.Depth != 0 {
		t.Fatalf("the acknowledged snapshot left %+v, %v", stats, err)
	}
}

func TestOutboxBlobRejectsTampering(t *testing.T) {
	secret := testSecret(3)
	raw, err := sealBlob(secret, "cluster-1", []byte(`{"head":1,"entries":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openBlob(testSecret(4), "cluster-1", raw); err == nil {
		t.Fatal("a batch opened under another secret")
	}
	if _, err := openBlob(secret, "cluster-2", raw); err == nil {
		t.Fatal("a batch opened for another cluster")
	}
	// Flip one character of the sealed payload and re-encode, so the change is
	// guaranteed to land in the ciphertext rather than in whitespace.
	var blob outboxBlob
	if err := json.Unmarshal(raw, &blob); err != nil {
		t.Fatal(err)
	}
	payload := []byte(blob.Payload)
	if payload[0] == 'A' {
		payload[0] = 'B'
	} else {
		payload[0] = 'A'
	}
	blob.Payload = string(payload)
	tampered, err := json.Marshal(blob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openBlob(secret, "cluster-1", tampered); err == nil {
		t.Fatal("a tampered batch opened")
	}
}
