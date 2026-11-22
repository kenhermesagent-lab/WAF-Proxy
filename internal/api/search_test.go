package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/rbac"
)

// A reader with traffic access can search the event log, but the same query
// must not reveal that a banned address exists unless the role can read
// policies. The global search route is outside the generic area check, so the
// handler itself has to enforce this.
func TestSearchHidesBansFromRolesWithoutPolicyAccess(t *testing.T) {
	srv, st, adminToken, csrf := newObservabilityServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/bans",
		strings.NewReader(`{"cidr":"203.0.113.44","reason":"search test"}`))
	req.Host = "gui.local"
	req.RemoteAddr = "10.0.0.10:5000"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: adminToken})
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/bans = %d: %s", rec.Code, rec.Body.String())
	}

	role := &model.Role{Name: "Traffic auditor", Permissions: []string{rbac.Permission("traffic", "read")}}
	if err := st.CreateRole(role); err != nil {
		t.Fatalf("create role: %v", err)
	}
	uid, err := st.CreateUserWithRole("auditor", "unused", "", "", false, role.ID)
	if err != nil {
		t.Fatalf("create auditor: %v", err)
	}
	auditorToken, _ := wfcrypto.RandomToken(32)
	if err := st.CreateSession(auditorToken, uid, "auditor-csrf", "10.0.0.11", "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create auditor session: %v", err)
	}

	search := func(token string) []searchResult {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/search?q=203.0.113.44", nil)
		req.Host = "gui.local"
		req.RemoteAddr = "10.0.0.10:5000"
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/search = %d: %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Results []searchResult `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode search: %v", err)
		}
		return out.Results
	}

	seen := false
	for _, r := range search(adminToken) {
		if r.Kind == "ban" && r.Title == "203.0.113.44/32" {
			seen = true
		}
	}
	if !seen {
		t.Fatal("administrator search did not return the ban")
	}
	for _, r := range search(auditorToken) {
		if r.Kind == "ban" {
			t.Fatalf("traffic-only role received a ban result: %+v", r)
		}
	}
}
