package api

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

// TestBundleEnableAndConsoleProviders covers the console-managed bundle page:
// shipped packs start off and can be switched on, and providers are added and
// removed from the database instead of an environment variable.
func TestBundleEnableAndConsoleProviders(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	m, err := bundle.New(bundle.Config{
		Dir: t.TempDir(),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	srv.SetBundles(m)

	snapshot := func(rec *httptest.ResponseRecorder) bundleSnapshot {
		t.Helper()
		var snap bundleSnapshot
		if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
			t.Fatal(err)
		}
		return snap
	}
	find := func(snap bundleSnapshot, name string) bundleView {
		t.Helper()
		for _, b := range snap.Bundles {
			if b.Name == name {
				return b
			}
		}
		t.Fatalf("bundle %s missing from the snapshot", name)
		return bundleView{}
	}

	snap := snapshot(authed(t, srv, token, csrf, http.MethodGet, "/api/bundles", ""))
	if b := find(snap, "secret-probes"); !b.Builtin || b.Enabled {
		t.Fatalf("shipped pack = %+v, want built-in and off", b)
	}

	on := authed(t, srv, token, csrf, http.MethodPost, "/api/bundles/enable", `{"name":"secret-probes","enabled":true}`)
	if on.Code != http.StatusOK {
		t.Fatalf("enable = %d: %s", on.Code, on.Body.String())
	}
	if b := find(snapshot(on), "secret-probes"); !b.Enabled {
		t.Fatalf("pack still off after enabling: %+v", b)
	}
	if unknown := authed(t, srv, token, csrf, http.MethodPost, "/api/bundles/enable", `{"name":"nope","enabled":true}`); unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown bundle = %d, want 400", unknown.Code)
	}

	priv, err := bundle.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	body := `{"name":"vendor-a","url":"https://a.example/manifest.json","public_key":"` + pub + `"}`
	saved := authed(t, srv, token, csrf, http.MethodPut, "/api/bundles/providers", body)
	if saved.Code != http.StatusOK {
		t.Fatalf("save provider = %d: %s", saved.Code, saved.Body.String())
	}
	if snap := snapshot(saved); len(snap.Providers) != 1 || !snap.Configured {
		t.Fatalf("providers after save = %+v", snap.Providers)
	}
	raw, err := srv.st.GetSetting(bundle.SettingsKey)
	if err != nil || !strings.Contains(raw, "vendor-a") {
		t.Fatalf("stored providers = %q, err %v", raw, err)
	}

	bad := authed(t, srv, token, csrf, http.MethodPut, "/api/bundles/providers",
		`{"name":"vendor-b","url":"ftp://a.example/manifest.json","public_key":"`+pub+`"}`)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("invalid provider = %d, want 400: %s", bad.Code, bad.Body.String())
	}

	removed := authed(t, srv, token, csrf, http.MethodDelete, "/api/bundles/providers?name=vendor-a", "")
	if removed.Code != http.StatusOK {
		t.Fatalf("remove provider = %d: %s", removed.Code, removed.Body.String())
	}
	if snap := snapshot(removed); len(snap.Providers) != 0 || snap.Configured {
		t.Fatalf("providers after removal = %+v", snap.Providers)
	}
	if missing := authed(t, srv, token, csrf, http.MethodDelete, "/api/bundles/providers?name=vendor-a", ""); missing.Code != http.StatusNotFound {
		t.Fatalf("removing an unknown provider = %d, want 404", missing.Code)
	}
}
