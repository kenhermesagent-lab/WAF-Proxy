package ha

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityIsStableAcrossReload(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if Fingerprint(first.Leaf) != Fingerprint(second.Leaf) {
		t.Fatal("reloading the identity changed its fingerprint")
	}
	if first.Node == "" || first.Node != second.Node {
		t.Fatalf("node id = %q then %q", first.Node, second.Node)
	}
	for _, name := range []string{"tls.crt", "tls.key", "node.json"} {
		info, err := os.Stat(filepath.Join(RoleDir(dir), name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 600", name, info.Mode().Perm())
		}
	}
}

func TestFingerprintNormalization(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	fp := Fingerprint(id.Leaf)
	if normalizeFingerprint(fp) != fp {
		t.Fatal("normalizing a fingerprint changed it")
	}
	grouped := ""
	for i, r := range fp {
		if i > 0 && i%2 == 0 {
			grouped += ":"
		}
		grouped += string(r)
	}
	if normalizeFingerprint(grouped) != fp {
		t.Fatal("grouped and colon-separated fingerprints do not normalize to the same value")
	}
}

func TestPairRecordValidated(t *testing.T) {
	dir := t.TempDir()
	if pair, err := LoadPair(dir); err != nil || pair != nil {
		t.Fatalf("unpaired load = %+v, %v", pair, err)
	}
	bad := &Pair{ClusterID: "c", PeerFingerprint: "f", Secret: "short"}
	if err := SavePair(dir, bad); err == nil {
		t.Fatal("SavePair accepted a short secret")
	}
	pair, err := NewPair("node-a", "10.0.0.11", "abc")
	if err != nil {
		t.Fatal(err)
	}
	if err := SavePair(dir, pair); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPair(dir)
	if err != nil || got == nil || got.ClusterID != pair.ClusterID {
		t.Fatalf("LoadPair = %+v, %v", got, err)
	}
	info, err := os.Stat(filepath.Join(RoleDir(dir), "pair.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("pair.json mode = %o, want 600", info.Mode().Perm())
	}
}
