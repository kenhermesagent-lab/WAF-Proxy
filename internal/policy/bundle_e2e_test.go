package policy

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
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/bundle"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

// bundleChannel is the publisher side of the channel: a signed manifest served
// with an ETag, and the pack file it points at.
type bundleChannel struct {
	mu          sync.Mutex
	manifest    []byte
	etag        string
	packs       map[string][]byte
	fetches     int
	notModified int
}

func (c *bundleChannel) serve() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.fetches++
		if c.etag != "" && r.Header.Get("If-None-Match") == c.etag {
			c.notModified++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if c.etag != "" {
			w.Header().Set("ETag", c.etag)
		}
		_, _ = w.Write(c.manifest)
	})
	mux.HandleFunc("/packs/", func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		body, ok := c.packs[r.URL.Path]
		c.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	})
	return httptest.NewServer(mux)
}

// publish signs a new manifest for one pack, the way a publisher would.
func (c *bundleChannel) publish(t *testing.T, priv ed25519.PrivateKey, seq int64, pack bundle.Pack) {
	t.Helper()
	raw, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	path := "/packs/" + pack.Bundle + ".json"
	manifest, err := bundle.SignManifest(bundle.Manifest{
		Sequence: seq,
		Bundles: []bundle.Ref{{
			Name: pack.Bundle, Version: pack.Version, Rules: len(pack.Rules),
			Size: int64(len(raw)), SHA256: hex.EncodeToString(sum[:]), Path: path,
		}},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.manifest = manifest
	c.packs = map[string][]byte{path: raw}
	c.etag = `"` + pack.Version + `"`
}

func (c *bundleChannel) counts() (fetches, notModified int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fetches, c.notModified
}

// TestBundleChannelReachesABlockingVerdict walks the whole path a real install
// takes: the manager fetches and verifies a signed channel, a 304 leaves
// everything alone, a version bump replaces the pack while keeping the previous
// one, and switching the profile to block turns a matching request into a 403.
func TestBundleChannelReachesABlockingVerdict(t *testing.T) {
	priv, err := bundle.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	ch := &bundleChannel{}
	srv := ch.serve()
	defer srv.Close()

	pol, st, _ := newEngine(t)
	profile := model.Profile{
		Name: "bundle site", Mode: "block", Paranoia: 1, Anomaly: 5,
		AllowedMethods: "GET,HEAD", MaxBody: 131072,
		BundleModes: map[string]string{"cve-2026-11": model.BundleLog},
	}
	if err := st.CreateProfile(&profile); err != nil {
		t.Fatal(err)
	}

	pack := func(version string) bundle.Pack {
		return bundle.Pack{Bundle: "cve-2026-11", Version: version, Rules: []waf.BundleRule{{
			ID: 990417, Message: "template injection probe", Severity: "CRITICAL",
			Target: "REQUEST_URI", Operator: "@contains /wp-login.php",
		}}}
	}
	ch.publish(t, priv, 1, pack("2026.11.23-1"))

	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := bundle.New(bundle.Config{
		Dir: dir,
		Providers: []bundle.Provider{{
			Name: "test", URL: srv.URL + "/manifest.json", PublicKey: hex.EncodeToString(pub),
		}},
		Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	// The same wiring main.go uses: the policy layer pulls the rules and an
	// install reloads the WAF.
	pol.SetBundleRules(m.Rules)
	m.OnChange(func() {
		if err := pol.ReloadWAF(); err != nil {
			t.Errorf("reload after install: %v", err)
		}
	})

	ctx := context.Background()
	proxy := &model.Proxy{ID: 1, Hostname: "app.example", Enabled: true, ProfileID: &profile.ID, WAFMode: "inherit"}
	inspect := func(path string) (model.Verdict, WAFInfo) {
		req := httptest.NewRequest("GET", "https://app.example"+path, nil)
		return pol.Inspect(&Request{
			Proxy: proxy, Host: "app.example", Method: "GET", Path: path,
			Addr: netip.MustParseAddr("203.0.113.9"), HTTP: req,
		})
	}

	// 1. The first check installs the advertised pack.
	if err := m.Check(ctx); err != nil {
		t.Fatal(err)
	}
	first := m.Status()
	if first.Providers[0].Sequence != 1 || len(first.Bundles) != 1 || first.Bundles[0].Version != "2026.11.23-1" {
		t.Fatalf("after first check = %+v, want sequence 1 and the advertised pack", first)
	}
	if got := m.RuleIndex()[990417]; got.Version != "2026.11.23-1" {
		t.Fatalf("rule index = %+v, want the installed version", got)
	}

	// It matches, but the profile still logs: installing a pack must not start
	// refusing traffic on its own.
	if v, _ := inspect("/wp-login.php"); v.Action != "log" || v.Rule != "990417" {
		t.Fatalf("default mode verdict = %+v, want a logged 990417", v)
	}

	// 2. The next check is a 304: nothing is refetched, nothing is lost.
	if err := m.Check(ctx); err != nil {
		t.Fatal(err)
	}
	fetches, notModified := ch.counts()
	if fetches != 2 || notModified != 1 {
		t.Fatalf("channel saw %d fetches and %d 304s, want 2 and 1", fetches, notModified)
	}
	if again := m.Status(); again.Providers[0].Sequence != 1 || len(again.Bundles) != 1 || again.Bundles[0].Version != "2026.11.23-1" {
		t.Fatalf("after 304 = %+v, want the state to be untouched", again)
	}

	// 3. A version bump is installed and the previous version is kept.
	ch.publish(t, priv, 2, pack("2026.11.23-2"))
	if err := m.Check(ctx); err != nil {
		t.Fatal(err)
	}
	bumped := m.Status()
	if bumped.Providers[0].Sequence != 2 || len(bumped.Bundles) != 1 || bumped.Bundles[0].Version != "2026.11.23-2" {
		t.Fatalf("after bump = %+v, want sequence 2 and the new version", bumped)
	}
	if got := m.RuleIndex()[990417]; got.Version != "2026.11.23-2" {
		t.Fatalf("rule index = %+v, want the bumped version", got)
	}
	versions, err := os.ReadDir(filepath.Join(dir, "cve-2026-11"))
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 {
		t.Fatalf("kept %d pack versions on disk, want the current one and the previous", len(versions))
	}
	if v, _ := inspect("/wp-login.php"); v.Action != "log" {
		t.Fatalf("verdict before the switch = %+v, want a log", v)
	}

	// 4. The operator allows this bundle to block on the profile.
	profile.BundleModes = map[string]string{"cve-2026-11": model.BundleBlock}
	if err := st.UpdateProfile(&profile); err != nil {
		t.Fatal(err)
	}
	if err := pol.ReloadWAF(); err != nil {
		t.Fatal(err)
	}

	verdict, info := inspect("/wp-login.php")
	if verdict.Action != "block" || verdict.Status != http.StatusForbidden || verdict.Rule != "990417" {
		t.Fatalf("block mode verdict = %+v, want a 403 on 990417", verdict)
	}
	if info.Label != "bundle" || info.RuleID != 990417 {
		t.Fatalf("block info = %+v, want the bundle rule", info)
	}
	if v, _ := inspect("/index.html"); v.Action == "block" {
		t.Fatalf("an unrelated request was refused: %+v", v)
	}
}
