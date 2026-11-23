package ha

import (
	"strings"
	"testing"
)

func TestMasterKeySealRoundTrip(t *testing.T) {
	secret := make([]byte, 32)
	key := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
		key[i] = byte(255 - i)
	}
	blob, err := SealMasterKey(secret, "cluster-1", key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenMasterKey(secret, "cluster-1", blob)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(key) {
		t.Fatal("the master key did not survive the envelope")
	}
	if _, err := OpenMasterKey(secret, "cluster-2", blob); err == nil {
		t.Fatal("the envelope opened under another cluster id")
	}
	other := make([]byte, 32)
	if _, err := OpenMasterKey(other, "cluster-1", blob); err == nil {
		t.Fatal("the envelope opened under another secret")
	}
	tampered := blob[:len(blob)-2] + "AA"
	if _, err := OpenMasterKey(secret, "cluster-1", tampered); err == nil {
		t.Fatal("a tampered envelope opened")
	}
}

func TestSaveMasterKeyRefusesReplacement(t *testing.T) {
	dir := t.TempDir()
	first := make([]byte, 32)
	second := make([]byte, 32)
	second[0] = 1
	if err := SaveMasterKey(dir, first); err != nil {
		t.Fatal(err)
	}
	if err := SaveMasterKey(dir, first); err != nil {
		t.Fatalf("saving the same key twice failed: %v", err)
	}
	if err := SaveMasterKey(dir, second); err == nil {
		t.Fatal("a different key overwrote the stored one")
	}
	got, err := LoadMasterKey(dir)
	if err != nil || string(got) != string(first) {
		t.Fatalf("LoadMasterKey = %x, %v", got, err)
	}
}

func TestUnpairKeepsRoleAndKey(t *testing.T) {
	dir := t.TempDir()
	node := &Node{NodeID: "node-a", Role: RoleActive, Epoch: 3, Peer: "10.0.0.11:9443"}
	if err := Save(dir, node); err != nil {
		t.Fatal(err)
	}
	pair, err := NewPair("node-a", "10.0.0.11:9443", strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := SavePair(dir, pair); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if err := SaveMasterKey(dir, key); err != nil {
		t.Fatal(err)
	}
	if _, err := WritePairingCode(dir); err != nil {
		t.Fatal(err)
	}
	if err := Unpair(dir); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadPair(dir); err != nil || got != nil {
		t.Fatalf("pair after unpair = %+v, %v", got, err)
	}
	after, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if after.Role != RoleActive || after.Peer != "" || after.NodeID != "node-a" {
		t.Fatalf("role after unpair = %+v", after)
	}
	if k, err := LoadMasterKey(dir); err != nil || string(k) != string(key) {
		t.Fatal("unpair removed the master key")
	}
	if err := CheckPairingCode(dir, "WAF-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GG"); err == nil {
		t.Fatal("unpair left a usable pairing code")
	}
}
