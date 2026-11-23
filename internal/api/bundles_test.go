package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

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
