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
	"strings"
	"testing"
	"time"

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
		Dir: dir,
		Providers: []Provider{{
			Name: "test", URL: url, PublicKey: hex.EncodeToString(pub),
		}},
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
	if got := m.Status().Providers[0].Sequence; got != 2 {
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

// TestProvidersAreCheckedIndependently covers the multi-provider channel: two
// manifest URLs with their own publisher keys, each with its own sequence.
func TestProvidersAreCheckedIndependently(t *testing.T) {
	privA, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	privB, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubA := privA.Public().(ed25519.PublicKey)
	pubB := privB.Public().(ed25519.PublicKey)

	manifestA, packA := signedChannel(t, privA, 1, testPack("1"))
	packB := Pack{Bundle: "edge-signatures", Version: "1", Rules: []waf.BundleRule{{
		ID: 990418, Message: "scan signature", Severity: "ERROR",
		Target: "REQUEST_URI", Operator: "@contains /.git/config",
	}}}
	manifestB, rawB := signedChannel(t, privB, 1, packB)
	chA := &channel{manifest: manifestA, packs: map[string][]byte{"/packs/cve-2026-11.json": packA}}
	chB := &channel{manifest: manifestB, packs: map[string][]byte{"/packs/edge-signatures.json": rawB}}
	srvA, srvB := chA.serve(), chB.serve()
	defer srvA.Close()
	defer srvB.Close()

	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := New(Config{Dir: dir, Interval: time.Minute, Log: log, Providers: []Provider{
		{Name: "vendor-a", URL: srvA.URL + "/manifest.json", PublicKey: hex.EncodeToString(pubA)},
		{Name: "vendor-b", URL: srvB.URL + "/manifest.json", PublicKey: hex.EncodeToString(pubB)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	if err := m.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := m.Status()
	if len(st.Providers) != 2 || st.Providers[0].Name != "vendor-a" || !st.Providers[0].Configured {
		t.Fatalf("providers = %+v", st.Providers)
	}
	if st.Providers[0].Sequence != 1 || st.Providers[1].Sequence != 1 {
		t.Fatalf("sequences = %d/%d, want 1/1", st.Providers[0].Sequence, st.Providers[1].Sequence)
	}
	owners := map[string]string{}
	for _, b := range st.Bundles {
		owners[b.Name] = b.Provider
	}
	if owners["cve-2026-11"] != "vendor-a" || owners["edge-signatures"] != "vendor-b" {
		t.Fatalf("bundle owners = %+v", owners)
	}
	if len(m.Rules()) != 2 {
		t.Fatalf("installed packs = %d, want 2", len(m.Rules()))
	}

	// The per-provider button refreshes only that provider.
	chA.manifest = manifestA
	if err := m.CheckProvider(context.Background(), "vendor-a"); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckProvider(context.Background(), "nobody"); err == nil {
		t.Fatal("checking an unknown provider was accepted")
	}

	// A name belongs to the provider that installed it: the second publisher
	// cannot take it over, and the first pack keeps serving.
	collidePack := testPack("9")
	collide, rawCollide := signedChannel(t, privB, 2, collidePack)
	chB.manifest = collide
	chB.packs["/packs/cve-2026-11.json"] = rawCollide
	if err := m.Check(context.Background()); err == nil {
		t.Fatal("two providers installed a bundle with the same name")
	}
	if got := m.installedVersion(m.providers[0], "cve-2026-11"); got != "1" {
		t.Fatalf("the owned bundle was replaced: version %q", got)
	}
	if !strings.Contains(m.Status().Providers[1].Error, "already provided by vendor-a") {
		t.Fatalf("provider-b error = %q", m.Status().Providers[1].Error)
	}

	// Provider B goes away: provider A still updates, and B's installed pack
	// keeps serving while its failure is reported.
	srvB.Close()
	nextA, nextPackA := signedChannel(t, privA, 2, testPack("2"))
	chA.manifest, chA.packs["/packs/cve-2026-11.json"] = nextA, nextPackA
	err = m.Check(context.Background())
	if err == nil {
		t.Fatal("a failed provider was not reported")
	}
	if !strings.Contains(err.Error(), "vendor-b") {
		t.Fatalf("error = %q, want it to name vendor-b", err)
	}
	if got := m.installedVersion(m.providers[0], "cve-2026-11"); got != "2" {
		t.Fatalf("reachable provider did not update: %q", got)
	}
	if got := m.installedVersion(m.providers[1], "edge-signatures"); got != "1" {
		t.Fatalf("unreachable provider lost its pack: %q", got)
	}

	// A restart keeps both packs and the sequence each provider reached.
	restarted, err := New(Config{Dir: dir, Interval: time.Minute, Log: log, Providers: []Provider{
		{Name: "vendor-a", URL: srvA.URL + "/manifest.json", PublicKey: hex.EncodeToString(pubA)},
		{Name: "vendor-b", URL: srvB.URL + "/manifest.json", PublicKey: hex.EncodeToString(pubB)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Load(); err != nil {
		t.Fatal(err)
	}
	if len(restarted.Rules()) != 2 {
		t.Fatalf("packs after restart = %+v", restarted.Rules())
	}
	if got := restarted.Status().Providers[0].Sequence; got != 2 {
		t.Fatalf("sequence after restart = %d, want 2", got)
	}
}

func TestParseProviders(t *testing.T) {
	got, err := ParseProviders(`[{"name":"vendor-a","url":"https://a.example/manifest.json","public_key":"abc"}]`, "", "")
	if err != nil || len(got) != 1 || got[0].Name != "vendor-a" || got[0].URL != "https://a.example/manifest.json" {
		t.Fatalf("providers = %+v, err = %v", got, err)
	}
	legacy, err := ParseProviders("", "https://b.example/manifest.json", "key")
	if err != nil || len(legacy) != 1 || legacy[0].Name != "default" {
		t.Fatalf("legacy provider = %+v, err = %v", legacy, err)
	}
	if _, err := ParseProviders(`[{"name":"a"}]`, "", ""); err == nil {
		t.Fatal("a provider without a url and key was accepted")
	}
	if _, err := ParseProviders("not json", "", ""); err == nil {
		t.Fatal("invalid JSON was accepted")
	}

	// New rejects duplicate names and a URL that is not a channel.
	pub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	key := hex.EncodeToString(pub.Public().(ed25519.PublicKey))
	if _, err := New(Config{Providers: []Provider{
		{Name: "a", URL: "https://a.example/m.json", PublicKey: key},
		{Name: "a", URL: "https://b.example/m.json", PublicKey: key},
	}}); err == nil {
		t.Fatal("duplicate provider names were accepted")
	}
	if _, err := New(Config{Providers: []Provider{{Name: "a", URL: "file:///tmp/m.json", PublicKey: key}}}); err == nil {
		t.Fatal("a non-http provider URL was accepted")
	}
}
