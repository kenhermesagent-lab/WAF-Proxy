package bundle

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

type channel struct {
	manifest     []byte
	packs        map[string][]byte
	etag         string
	manifestHits int
}

func (c *channel) serve() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		c.manifestHits++
		if c.etag != "" && r.Header.Get("If-None-Match") == c.etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if c.etag != "" {
			w.Header().Set("ETag", c.etag)
		}
		_, _ = w.Write(c.manifest)
	})
	mux.HandleFunc("/packs/", func(w http.ResponseWriter, r *http.Request) {
		body, ok := c.packs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	})
	return httptest.NewServer(mux)
}

func signedChannel(t *testing.T, priv ed25519.PrivateKey, seq int64, pack Pack) ([]byte, []byte) {
	t.Helper()
	raw, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	manifest, err := SignManifest(Manifest{
		Sequence: seq,
		Bundles: []Ref{{
			Name: pack.Bundle, Version: pack.Version, Rules: len(pack.Rules),
			Size: int64(len(raw)), SHA256: hex.EncodeToString(sum[:]),
			Path: "/packs/" + pack.Bundle + ".json",
		}},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return manifest, raw
}

func testPack(version string) Pack {
	return Pack{Bundle: "cve-2026-11", Version: version, Rules: []waf.BundleRule{{
		ID: 990417, Message: "template injection probe", Severity: "CRITICAL",
		Target: "REQUEST_URI", Operator: "@contains {{7*7}}",
	}}}
}

func newTestManager(t *testing.T, dir, url string, pub ed25519.PublicKey) *Manager {
	t.Helper()
	m, err := New(Config{
		Dir: dir, URL: url, PublicKey: hex.EncodeToString(pub),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSignedChannelInstallsAndSurvivesRestart(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	manifest, rawPack := signedChannel(t, priv, 1, testPack("2026.11.23-04"))
	srv := (&channel{manifest: manifest, packs: map[string][]byte{"/packs/cve-2026-11.json": rawPack}}).serve()
	defer srv.Close()

	dir := t.TempDir()
	m := newTestManager(t, dir, srv.URL+"/manifest.json", pub)
	if !m.Enabled() {
		t.Fatal("a configured channel should be enabled")
	}
	changed := 0
	m.OnChange(func() { changed++ })
	if err := m.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	rules := m.Rules()
	if len(rules) != 1 || rules[0].Name != "cve-2026-11" || len(rules[0].Rules) != 1 {
		t.Fatalf("installed rules = %+v", rules)
	}
	if changed != 1 {
		t.Fatalf("change callback ran %d times, want 1", changed)
	}
	if m.RuleIndex()[990417].Bundle != "cve-2026-11" {
		t.Fatalf("rule index lost the pack: %+v", m.RuleIndex())
	}

	// A restart with no channel at all still serves the pack from disk.
	restarted := newTestManager(t, dir, "", pub)
	if got := restarted.Rules(); len(got) != 1 || got[0].Version != "2026.11.23-04" {
		t.Fatalf("after restart = %+v", got)
	}
	if restarted.Enabled() {
		t.Fatal("a manager without a URL must not fetch")
	}
}

func TestManifestSignatureIsRequired(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	_, rawPack := signedChannel(t, priv, 1, testPack("1"))
	// Same shape, different signature: nothing in it is trustworthy.
	tampered := []byte(`{"payload":{"sequence":1,"bundles":[]},"signature":"` + hex.EncodeToString([]byte("nope")) + `"}`)
	srv := (&channel{manifest: tampered, packs: map[string][]byte{"/packs/cve-2026-11.json": rawPack}}).serve()
	defer srv.Close()

	m := newTestManager(t, t.TempDir(), srv.URL+"/manifest.json", pub)
	if err := m.Check(context.Background()); err == nil {
		t.Fatal("a manifest with a forged signature was accepted")
	}
	if len(m.Rules()) != 0 {
		t.Fatal("nothing may be installed from an unverified manifest")
	}

	// And a wrong publisher key cannot read a valid manifest either.
	other, _ := GenerateKey()
	m2 := newTestManager(t, t.TempDir(), srv.URL+"/manifest.json", other.Public().(ed25519.PublicKey))
	if err := m2.Check(context.Background()); err == nil {
		t.Fatal("a manifest signed by another key was accepted")
	}
}

func TestChecksumAndRollbackAreRefused(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	manifest, rawPack := signedChannel(t, priv, 2, testPack("2"))
	ch := &channel{manifest: manifest, packs: map[string][]byte{"/packs/cve-2026-11.json": rawPack}, etag: `"v2"`}
	srv := ch.serve()
	defer srv.Close()

	dir := t.TempDir()
	m := newTestManager(t, dir, srv.URL+"/manifest.json", pub)
	if err := m.Check(context.Background()); err != nil {
		t.Fatal(err)
	}

	// A second check is cheap: the manifest answers 304 and nothing is fetched.
	if err := m.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ch.manifestHits != 2 {
		t.Fatalf("manifest fetched %d times, want 2", ch.manifestHits)
	}
	// A 304 must not reset the sequence, or the next check could accept a
	// mirror's older manifest.
	if got := m.Status().Sequence; got != 2 {
		t.Fatalf("sequence after 304 = %d, want 2", got)
	}

	// The same pack with a size the manifest does not advertise must not
	// replace the installed one.
	badManifest, _ := signedChannel(t, priv, 3, testPack("3"))
	ch.manifest = badManifest
	ch.packs["/packs/cve-2026-11.json"] = []byte(`{"bundle":"cve-2026-11","version":"3","rules":[]}`)
	ch.etag = `"v3"`
	if err := m.Check(context.Background()); err == nil {
		t.Fatal("a pack whose checksum does not match was installed")
	}
	if got := m.Rules(); len(got) != 1 || got[0].Version != "2" {
		t.Fatalf("a failed install replaced the working pack: %+v", got)
	}

	// An older manifest cannot roll the channel backwards.
	oldManifest, _ := signedChannel(t, priv, 1, testPack("1"))
	ch.manifest = oldManifest
	ch.etag = `"v1"`
	if err := m.Check(context.Background()); err == nil {
		t.Fatal("an older manifest sequence was accepted")
	}
}
