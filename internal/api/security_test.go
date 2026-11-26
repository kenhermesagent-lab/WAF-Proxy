package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// A run whose process died leaves no end time. Once it is older than the run
// budget it is reported abandoned, while one that just started still reads as
// running (no abandoned flag).
func TestUnfinishedRunShowsAbandoned(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	stale, err := st.CreateScanRun(&model.ScanRun{
		Target: "app.example.com", Trigger: "schedule", StartedAt: time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := st.CreateScanRun(&model.ScanRun{
		Target: "app.example.com", Trigger: "manual", StartedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := securityDo(t, srv, http.MethodGet, "/api/security/runs", "gui.local", token, csrf, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET runs = %d", rec.Code)
	}
	var listed struct {
		Runs []model.ScanRun `json:"runs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	seen := map[int64]model.ScanRun{}
	for _, run := range listed.Runs {
		seen[run.ID] = run
	}
	if !seen[stale].Abandoned {
		t.Fatalf("a run with no end an hour old was not abandoned: %+v", seen[stale])
	}
	if seen[fresh].Abandoned {
		t.Fatalf("a run that just started was abandoned: %+v", seen[fresh])
	}

	rec = securityDo(t, srv, http.MethodGet, "/api/security/runs/"+strconv.FormatInt(stale, 10), "gui.local", token, csrf, nil)
	var detail struct {
		Run model.ScanRun `json:"run"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if !detail.Run.Abandoned {
		t.Fatalf("the detail of an unfinished run was not abandoned: %+v", detail.Run)
	}
}

// Accepting through the API needs a reason, not just the page. A missing or
// blank reason is refused and nothing is written; a real one is stored trimmed.
func TestAcceptRequiresReason(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if _, _, err := st.MergeScanFindings(st.SiteID(), "app.example.com", []model.ScanFinding{{
		Key: "exposure:/.env", Stage: "backend", Class: "exposure",
		Title: "The application serves /.env", Severity: "high",
		Recommendation: "Remove the file", Note: "served HTTP 200",
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}

	for _, body := range []map[string]any{
		{"state": "accepted"},
		{"state": "accepted", "reason": "   "},
	} {
		rec := securityDo(t, srv, http.MethodPatch, "/api/security/findings/exposure%3A%2F.env", "gui.local", token, csrf, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("accept %v = %d (%s), want 400", body, rec.Code, rec.Body.String())
		}
	}
	listed, err := st.ListScanFindings("", "")
	if err != nil || len(listed) != 1 {
		t.Fatalf("findings = %+v, %v", listed, err)
	}
	if listed[0].State != "open" || listed[0].Reason != "" {
		t.Fatalf("a refused accept changed the finding: %+v", listed[0])
	}

	rec := securityDo(t, srv, http.MethodPatch, "/api/security/findings/exposure%3A%2F.env", "gui.local", token, csrf,
		map[string]any{"state": "accepted", "reason": "  risk accepted until Q3  "})
	if rec.Code != http.StatusOK {
		t.Fatalf("accept with a reason = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	listed, err = st.ListScanFindings("", "")
	if err != nil || len(listed) != 1 {
		t.Fatalf("findings = %+v, %v", listed, err)
	}
	if listed[0].State != "accepted" || listed[0].Reason != "risk accepted until Q3" {
		t.Fatalf("accepted finding = %+v, want the reason stored trimmed", listed[0])
	}
	if listed[0].Note != "served HTTP 200" {
		t.Fatalf("scan note = %q, want it untouched", listed[0].Note)
	}
}

// Accepting stores the reason in its own field, and a reopen keeps it while
// the scan's note stays what the run wrote.
func TestAcceptedReasonSurvivesReopen(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if _, _, err := st.MergeScanFindings(st.SiteID(), "app.example.com", []model.ScanFinding{{
		Key: "exposure:/.env", Stage: "backend", Class: "exposure",
		Title: "The application serves /.env", Severity: "high",
		Recommendation: "Remove the file", Note: "served HTTP 200",
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}

	rec := securityDo(t, srv, http.MethodPatch, "/api/security/findings/exposure%3A%2F.env", "gui.local", token, csrf,
		map[string]any{"state": "accepted", "reason": "risk accepted until Q3"})
	if rec.Code != http.StatusOK {
		t.Fatalf("accept = %d (%s)", rec.Code, rec.Body.String())
	}

	rec = securityDo(t, srv, http.MethodPatch, "/api/security/findings/exposure%3A%2F.env", "gui.local", token, csrf,
		map[string]any{"state": "open"})
	if rec.Code != http.StatusOK {
		t.Fatalf("reopen = %d (%s)", rec.Code, rec.Body.String())
	}

	rec = securityDo(t, srv, http.MethodGet, "/api/security/findings", "gui.local", token, csrf, nil)
	var listed struct {
		Findings []model.ScanFinding `json:"findings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil || len(listed.Findings) != 1 {
		t.Fatalf("findings = %+v, %v", listed.Findings, err)
	}
	got := listed.Findings[0]
	if got.State != "open" || got.Reason != "risk accepted until Q3" || got.Note != "served HTTP 200" {
		t.Fatalf("after reopen: %+v, want open with the reason and the scan note kept", got)
	}
}

// A standalone install has no active node to defer to, so the role check must
// not refuse its manual runs. A foreign target is still a 404.
func TestRunAllowedOnStandaloneNode(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	srv.haStatus = func() HAStatus { return HAStatus{Role: "standalone", State: "standalone"} }

	rec := securityDo(t, srv, http.MethodPost, "/api/security/runs", "gui.local", token, csrf,
		map[string]any{"targets": []int64{9999}})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("standalone run = %d (%s), want 404 for the missing target, not a role refusal", rec.Code, rec.Body.String())
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
