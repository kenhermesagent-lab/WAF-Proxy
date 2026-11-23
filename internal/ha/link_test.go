package ha

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func startJoinServer(t *testing.T, dataDir string, masterKey []byte, st *store.Store) (*Identity, string) {
	t.Helper()
	id, err := LoadOrCreateIdentity(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewJoinServer(id, dataDir, masterKey, st, discardLog())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := &http.Server{Handler: srv.Handler()}
	go func() { _ = httpSrv.Serve(tls.NewListener(ln, srv.TLSConfig())) }()
	t.Cleanup(func() { _ = httpSrv.Close() })
	return id, ln.Addr().String()
}

func TestJoinEndToEnd(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	idA, addr := startJoinServer(t, dirA, nil, nil)
	code, err := WritePairingCode(dirA)
	if err != nil {
		t.Fatal(err)
	}
	pairB, err := Join(context.Background(), dirB, addr, Fingerprint(idA.Leaf), code)
	if err != nil {
		t.Fatal(err)
	}
	if pairB.ClusterID == "" || len(pairB.Secret) != 64 {
		t.Fatalf("pair B = %+v", pairB)
	}
	idB, err := LoadOrCreateIdentity(dirB)
	if err != nil {
		t.Fatal(err)
	}
	if pairB.PeerFingerprint != Fingerprint(idA.Leaf) {
		t.Fatalf("B pinned %s, want %s", pairB.PeerFingerprint, Fingerprint(idA.Leaf))
	}
	pairA, err := LoadPair(dirA)
	if err != nil {
		t.Fatal(err)
	}
	if pairA == nil || pairA.ClusterID != pairB.ClusterID || pairA.Secret != pairB.Secret {
		t.Fatalf("A pair = %+v, B pair = %+v", pairA, pairB)
	}
	if pairA.PeerFingerprint != Fingerprint(idB.Leaf) {
		t.Fatalf("A pinned %s, want %s", pairA.PeerFingerprint, Fingerprint(idB.Leaf))
	}
	// The code is single use.
	if err := CheckPairingCode(dirA, code); err == nil {
		t.Fatal("the pairing code survived a successful join")
	}
}

func TestJoinTransfersMasterKey(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i + 1)
	}
	idA, addr := startJoinServer(t, dirA, master, nil)
	code, err := WritePairingCode(dirA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Join(context.Background(), dirB, addr, Fingerprint(idA.Leaf), code); err != nil {
		t.Fatal(err)
	}
	got, err := LoadMasterKey(dirB)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(master) {
		t.Fatalf("joined node master key = %x, want %x", got, master)
	}
}

func TestJoinRefusesWrongCode(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	idA, addr := startJoinServer(t, dirA, nil, nil)
	if _, err := WritePairingCode(dirA); err != nil {
		t.Fatal(err)
	}
	if _, err := Join(context.Background(), dirB, addr, Fingerprint(idA.Leaf), "WAF-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GG"); err == nil {
		t.Fatal("join accepted the wrong code")
	}
	if pair, _ := LoadPair(dirB); pair != nil {
		t.Fatal("a failed join left a pair record")
	}
}

func TestJoinRefusesWrongPin(t *testing.T) {
	dirA, dirB, dirC := t.TempDir(), t.TempDir(), t.TempDir()
	_, addr := startJoinServer(t, dirA, nil, nil)
	code, err := WritePairingCode(dirA)
	if err != nil {
		t.Fatal(err)
	}
	other, err := LoadOrCreateIdentity(dirC)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Join(context.Background(), dirB, addr, Fingerprint(other.Leaf), code); err == nil {
		t.Fatal("join accepted a fingerprint that does not match the active node")
	}
	if pair, _ := LoadPair(dirB); pair != nil {
		t.Fatal("a failed join left a pair record")
	}
}

func TestJoinRefusesExpiredCode(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	idA, addr := startJoinServer(t, dirA, nil, nil)
	code := "WAF-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GG"
	raw, err := json.Marshal(pendingCode{Hash: codeHash(code), ExpiresAt: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(RoleDir(dirA), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Join(RoleDir(dirA), "pairing.json"), raw); err != nil {
		t.Fatal(err)
	}
	if _, err := Join(context.Background(), dirB, addr, Fingerprint(idA.Leaf), code); err == nil {
		t.Fatal("join accepted an expired code")
	}
}

func TestAttemptLimiter(t *testing.T) {
	l := newAttemptLimiter(2, time.Minute)
	now := time.Now()
	if !l.allow("a", now) || !l.allow("a", now) {
		t.Fatal("first two attempts were refused")
	}
	if l.allow("a", now) {
		t.Fatal("third attempt was allowed")
	}
	if !l.allow("b", now) {
		t.Fatal("another address was limited")
	}
	if !l.allow("a", now.Add(2*time.Minute)) {
		t.Fatal("the window did not expire")
	}
}
