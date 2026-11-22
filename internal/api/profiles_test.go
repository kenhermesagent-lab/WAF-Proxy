package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// authed serves one authenticated request against the console handler.
func authed(t *testing.T, srv *Server, token, csrf, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "gui.local"
	req.RemoteAddr = "192.168.101.10:5000"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	if method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestProfileCreateAndDelete(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)

	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/profiles",
		`{"name":"Site strict","paranoia":3,"anomaly":4,"max_body":65536}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/profiles = %d: %s", rec.Code, rec.Body.String())
	}
	var created model.Profile
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if created.ID == 0 || created.Builtin || created.Name != "Site strict" || created.Paranoia != 3 {
		t.Fatalf("unexpected created profile: %+v", created)
	}
	if created.AllowedMethods == "" || created.Mode != "block" {
		t.Fatalf("created profile has unsafe defaults: %+v", created)
	}

	list := authed(t, srv, token, csrf, http.MethodGet, "/api/profiles", "")
	var profiles []model.Profile
	if err := json.Unmarshal(list.Body.Bytes(), &profiles); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	found := false
	for _, p := range profiles {
		if p.ID == created.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("created profile is missing from GET /api/profiles")
	}

	// The name is unique, so a second profile with it would be ambiguous in the
	// proxy form.
	dup := authed(t, srv, token, csrf, http.MethodPost, "/api/profiles", `{"name":"Site strict"}`)
	if dup.Code != http.StatusConflict {
		t.Fatalf("duplicate name = %d, want 409: %s", dup.Code, dup.Body.String())
	}

	// The seeded profiles are reference points and must stay.
	builtin := authed(t, srv, token, csrf, http.MethodDelete, "/api/profiles/1", "")
	if builtin.Code != http.StatusConflict {
		t.Fatalf("deleting a built-in profile = %d, want 409: %s", builtin.Code, builtin.Body.String())
	}

	del := authed(t, srv, token, csrf, http.MethodDelete, "/api/profiles/"+strconv.FormatInt(created.ID, 10), "")
	if del.Code != http.StatusOK {
		t.Fatalf("DELETE /api/profiles/%d = %d: %s", created.ID, del.Code, del.Body.String())
	}
}

func TestProfileDeleteRefusesSelectedProfile(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)

	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/profiles", `{"name":"In use"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create profile = %d: %s", rec.Code, rec.Body.String())
	}
	var created model.Profile
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	// profile_id is ON DELETE SET NULL, so deleting a selected profile would
	// quietly move the site to the default protection instead of failing.
	if _, err := st.CreateProxy(&model.Proxy{
		Hostname: "app.example.com", Enabled: true, ProfileID: &created.ID, WAFMode: "inherit",
	}); err != nil {
		t.Fatal(err)
	}

	del := authed(t, srv, token, csrf, http.MethodDelete, "/api/profiles/"+strconv.FormatInt(created.ID, 10), "")
	if del.Code != http.StatusConflict {
		t.Fatalf("delete of a selected profile = %d, want 409: %s", del.Code, del.Body.String())
	}
	if !strings.Contains(del.Body.String(), "assign another profile") {
		t.Fatalf("reason does not explain the fix: %s", del.Body.String())
	}
}
