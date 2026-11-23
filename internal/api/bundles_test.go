package api

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/bundle"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func TestProfileBundleModesRoundTrip(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)

	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/profiles", `{"name":"Bundle site"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create profile = %d: %s", rec.Code, rec.Body.String())
	}
	var created model.Profile
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	path := "/api/profiles/" + strconv.FormatInt(created.ID, 10)

	put := authed(t, srv, token, csrf, http.MethodPut, path,
		`{"bundle_modes":{"cve-2026-11":"block","owasp-extra":"off"}}`)
	if put.Code != http.StatusOK {
		t.Fatalf("PUT bundle_modes = %d: %s", put.Code, put.Body.String())
	}
	got, err := srv.st.GetProfile(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.BundleMode("cve-2026-11") != model.BundleBlock || got.BundleMode("owasp-extra") != model.BundleOff {
		t.Fatalf("stored modes = %+v", got.BundleModes)
	}
	if got.BundleMode("never-set") != model.BundleLog {
		t.Fatalf("an unset bundle must default to log, got %q", got.BundleMode("never-set"))
	}

	bad := authed(t, srv, token, csrf, http.MethodPut, path, `{"bundle_modes":{"cve-2026-11":"ban"}}`)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("invalid mode = %d, want 400: %s", bad.Code, bad.Body.String())
	}
}

func TestBundleEndpointsWithoutAChannel(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)

	list := authed(t, srv, token, csrf, http.MethodGet, "/api/bundles", "")
	if list.Code != http.StatusOK {
		t.Fatalf("GET /api/bundles = %d: %s", list.Code, list.Body.String())
	}
	var snap bundleSnapshot
	if err := json.Unmarshal(list.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Configured || len(snap.Bundles) != 0 {
		t.Fatalf("unconfigured channel = %+v", snap)
	}

	check := authed(t, srv, token, csrf, http.MethodPost, "/api/bundles/check", "")
	if check.Code != http.StatusConflict {
		t.Fatalf("check without a channel = %d, want 409", check.Code)
	}

	hits := authed(t, srv, token, csrf, http.MethodGet, "/api/bundles/hits?hours=24", "")
	if hits.Code != http.StatusOK {
		t.Fatalf("GET /api/bundles/hits = %d: %s", hits.Code, hits.Body.String())
	}
}

// TestBundleSnapshotListsProviders covers the multi-provider console view: the
// providers are reported separately, and an unknown name is a bad request
// rather than a fetch attempt.
func TestBundleSnapshotListsProviders(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	priv, err := bundle.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	m, err := bundle.New(bundle.Config{
		Dir: t.TempDir(),
		Providers: []bundle.Provider{
			{Name: "vendor-a", URL: "https://a.example/manifest.json", PublicKey: hex.EncodeToString(pub)},
			{Name: "vendor-b"},
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.SetBundles(m)

	rec := authed(t, srv, token, csrf, http.MethodGet, "/api/bundles", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/bundles = %d: %s", rec.Code, rec.Body.String())
	}
	var snap bundleSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if !snap.Configured || len(snap.Providers) != 2 {
		t.Fatalf("snapshot = %+v", snap)
	}
	if a := snap.Providers[0]; a.Name != "vendor-a" || !a.Configured || a.URL == "" || a.KeyID == "" {
		t.Fatalf("configured provider = %+v", a)
	}
	if b := snap.Providers[1]; b.Name != "vendor-b" || b.Configured {
		t.Fatalf("provider without a channel = %+v", b)
	}

	bad := authed(t, srv, token, csrf, http.MethodPost, "/api/bundles/check?provider=nobody", "")
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("checking an unknown provider = %d, want 400: %s", bad.Code, bad.Body.String())
	}
}
