package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/rbac"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// securitySession creates a role, an account and a session for the API tests.
func securitySession(t *testing.T, st *store.Store, username string, permissions []string) (string, string) {
	t.Helper()
	role := &model.Role{Name: "role-" + username, Permissions: permissions}
	if err := st.CreateRole(role); err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := st.CreateUserWithRole(username, hash, "", "", false, role.ID)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := wfcrypto.RandomToken(32)
	csrf, _ := wfcrypto.RandomToken(24)
	if err := st.CreateSession(token, uid, csrf, "10.0.0.11", "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return token, csrf
}

func securityDo(t *testing.T, srv *Server, method, path, host, token, csrf string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Host = host
	req.RemoteAddr = "10.0.0.11:5000"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// A role without the security area cannot read the page or start a run.
func TestSecurityRoutesRequirePermission(t *testing.T) {
	srv, st, _, _ := newObservabilityServer(t)
	token, csrf := securitySession(t, st, "settings-only", []string{
		rbac.Permission("settings", "read"), rbac.Permission("settings", "write"),
	})

	if rec := securityDo(t, srv, http.MethodGet, "/api/security/overview", "gui.local", token, csrf, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("GET overview = %d, want 403", rec.Code)
	}
	if rec := securityDo(t, srv, http.MethodPost, "/api/security/runs", "gui.local", token, csrf,
		map[string]any{"targets": []int64{1}}); rec.Code != http.StatusForbidden {
		t.Fatalf("POST runs = %d, want 403", rec.Code)
	}
}

// A settings grant is not a security grant: the scan can read the site and must
// still be refused.
func TestSecurityPermissionNotImpliedBySettings(t *testing.T) {
	srv, st, _, _ := newObservabilityServer(t)
	token, csrf := securitySession(t, st, "settings-reader", []string{rbac.Permission("settings", "read")})

	if rec := securityDo(t, srv, http.MethodGet, "/api/security/findings", "gui.local", token, csrf, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("GET findings with settings.read = %d, want 403", rec.Code)
	}
}

// A tenant can start a scan of its own hostnames only: another site's proxy id
// is a 404 and nothing is recorded.
func TestTenantCannotScanForeignSite(t *testing.T) {
	srv, st, _, _ := newObservabilityServer(t)
	foreign, err := st.CreateProxy(&model.Proxy{Hostname: "alpha.example.com", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	site, err := st.CreateSite("bravo", "Bravo", "console.bravo.test")
	if err != nil {
		t.Fatal(err)
	}
	bravo := st.InSite(site.ID)
	token, csrf := securitySession(t, bravo, "bravo-scanner", []string{
		rbac.Permission("security", "read"), rbac.SecurityRun,
	})

	rec := securityDo(t, srv, http.MethodPost, "/api/security/runs", site.ConsoleHost, token, csrf,
		map[string]any{"targets": []int64{foreign}})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("a foreign target = %d (%s), want 404", rec.Code, rec.Body.String())
	}
	runs, err := bravo.ListScanRuns(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 0 {
		t.Fatalf("the refused run was still recorded: %+v", runs)
	}
}

// The single pause switch stops a manual run before any request is sent.
func TestRunRefusedWhenPaused(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("security_paused", "1"); err != nil {
		t.Fatal(err)
	}
	id, err := st.CreateProxy(&model.Proxy{Hostname: "app.example.com", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	rec := securityDo(t, srv, http.MethodPost, "/api/security/runs", "gui.local", token, csrf,
		map[string]any{"targets": []int64{id}})
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST runs while paused = %d (%s), want 409", rec.Code, rec.Body.String())
	}
	runs, err := st.ListScanRuns(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 0 {
		t.Fatalf("a paused run was recorded: %+v", runs)
	}
}
