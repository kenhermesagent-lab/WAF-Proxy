package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func sendJSON(t *testing.T, srv *Server, method, token, csrf, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = "gui.local"
	req.RemoteAddr = "10.0.0.10:5000"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func getJSON(t *testing.T, srv *Server, token, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Host = "gui.local"
	req.RemoteAddr = "10.0.0.10:5000"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// newestSnapshotEntry returns the id of the newest audit entry carrying a
// snapshot for the given entity.
func newestSnapshotEntry(t *testing.T, srv *Server, token, entity string) int64 {
	t.Helper()
	rec := getJSON(t, srv, token, "/api/audit")
	if rec.Code != http.StatusOK {
		t.Fatalf("audit list status = %d: %s", rec.Code, rec.Body.String())
	}
	var list []model.AuditEntry
	decodeJSON(t, rec, &list)
	for _, e := range list {
		if e.Entity == entity {
			return e.ID
		}
	}
	t.Fatalf("no %s entry with a snapshot in %+v", entity, list)
	return 0
}

func TestPolicyUpdateSnapshotAndRollback(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	id, err := st.CreatePolicy(&model.Policy{Kind: "country_blacklist", Value: "RU", Action: "block", Scope: "global", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	body := `{"kind":"country_blacklist","value":"DE","action":"block","scope":"global","enabled":true}`
	if rec := sendJSON(t, srv, http.MethodPut, token, csrf, fmt.Sprintf("/api/policies/%d", id), body); rec.Code != http.StatusOK {
		t.Fatalf("update status = %d: %s", rec.Code, rec.Body.String())
	}

	entryID := newestSnapshotEntry(t, srv, token, "policy")
	rec := getJSON(t, srv, token, fmt.Sprintf("/api/audit/%d", entryID))
	if rec.Code != http.StatusOK {
		t.Fatalf("entry status = %d: %s", rec.Code, rec.Body.String())
	}
	var detail struct {
		Entry    model.AuditEntry     `json:"entry"`
		Snapshot *model.AuditSnapshot `json:"snapshot"`
	}
	decodeJSON(t, rec, &detail)
	if detail.Snapshot == nil || !strings.Contains(detail.Snapshot.Before, `"RU"`) || !strings.Contains(detail.Snapshot.After, `"DE"`) {
		t.Fatalf("unexpected snapshot: %+v", detail.Snapshot)
	}

	rb := sendJSON(t, srv, http.MethodPost, token, csrf, fmt.Sprintf("/api/audit/%d/rollback", entryID), "")
	if rb.Code != http.StatusOK {
		t.Fatalf("rollback status = %d: %s", rb.Code, rb.Body.String())
	}
	restored, err := st.GetPolicy(id)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Value != "RU" {
		t.Fatalf("policy value = %q, want RU", restored.Value)
	}

	// The rollback is itself audited and the hash chain still verifies.
	audit := getJSON(t, srv, token, "/api/audit")
	var list []model.AuditEntry
	decodeJSON(t, audit, &list)
	if list[0].Action != "policy.rollback" {
		t.Fatalf("newest audit action = %q", list[0].Action)
	}
	if _, problem, err := st.VerifyAuditChain(); err != nil || problem != "" {
		t.Fatalf("audit chain: %v %s", err, problem)
	}
}

func TestRollbackRefusesADeletion(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	id, err := st.CreatePolicy(&model.Policy{Kind: "country_blacklist", Value: "RU", Action: "block", Scope: "global", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if rec := sendJSON(t, srv, http.MethodDelete, token, csrf, fmt.Sprintf("/api/policies/%d", id), ""); rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d: %s", rec.Code, rec.Body.String())
	}
	entryID := newestSnapshotEntry(t, srv, token, "policy")
	if rec := sendJSON(t, srv, http.MethodPost, token, csrf, fmt.Sprintf("/api/audit/%d/rollback", entryID), ""); rec.Code != http.StatusConflict {
		t.Fatalf("rollback of a deletion status = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRollbackNeedsAStoredSnapshot(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	rec := getJSON(t, srv, token, "/api/audit")
	var list []model.AuditEntry
	decodeJSON(t, rec, &list)
	entryID := int64(1)
	if len(list) > 0 {
		entryID = list[len(list)-1].ID
	}
	if rec := sendJSON(t, srv, http.MethodPost, token, csrf, fmt.Sprintf("/api/audit/%d/rollback", entryID), ""); rec.Code != http.StatusNotFound {
		t.Fatalf("rollback without a snapshot status = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestProxyUpdateSnapshotKeepsChildren(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	created, err := st.CreateProxy(&model.Proxy{Hostname: "site.example.com", Enabled: true, WAFMode: "inherit", BotLevel: "light"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceUpstreams(created, []model.Upstream{{URL: "http://10.0.0.5:8080", Weight: 1, Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceRoutes(created, []model.Route{{Kind: "prefix", Match: "/api", Target: "http://10.0.0.5:8080", StripPrefix: true}}); err != nil {
		t.Fatal(err)
	}

	// Rename the site and swap its children, the way the proxy editor does.
	body := `{"hostname":"renamed.example.com","enabled":false,"waf_mode":"off",
		"upstreams":[{"url":"http://10.0.0.9:9000","weight":3,"enabled":true}],
		"routes":[{"kind":"prefix","match":"/v2","target":"http://10.0.0.9:9000"}]}`
	if rec := sendJSON(t, srv, http.MethodPut, token, csrf, fmt.Sprintf("/api/proxies/%d", created), body); rec.Code != http.StatusOK {
		t.Fatalf("update status = %d: %s", rec.Code, rec.Body.String())
	}
	edited, err := st.GetProxy(created)
	if err != nil || edited.Hostname != "renamed.example.com" {
		t.Fatalf("proxy after edit = %+v, %v", edited, err)
	}

	entryID := newestSnapshotEntry(t, srv, token, "proxy")
	rec := getJSON(t, srv, token, fmt.Sprintf("/api/audit/%d", entryID))
	var detail struct {
		Snapshot *model.AuditSnapshot `json:"snapshot"`
	}
	decodeJSON(t, rec, &detail)
	if detail.Snapshot == nil || !strings.Contains(detail.Snapshot.Before, "10.0.0.5") {
		t.Fatalf("proxy snapshot lost its upstreams: %+v", detail.Snapshot)
	}
	var raw map[string]any
	_ = json.Unmarshal([]byte(detail.Snapshot.Before), &raw)
	if _, ok := raw["proxy"]; !ok {
		t.Fatalf("proxy snapshot is not the wrapped shape: %s", detail.Snapshot.Before)
	}

	if rb := sendJSON(t, srv, http.MethodPost, token, csrf, fmt.Sprintf("/api/audit/%d/rollback", entryID), ""); rb.Code != http.StatusOK {
		t.Fatalf("rollback status = %d: %s", rb.Code, rb.Body.String())
	}

	// The site and both of its children come back as they were.
	restored, err := st.GetProxy(created)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Hostname != "site.example.com" || !restored.Enabled {
		t.Fatalf("proxy after rollback = %+v", restored)
	}
	ups, err := st.ListUpstreams(created)
	if err != nil || len(ups) != 1 || ups[0].URL != "http://10.0.0.5:8080" || ups[0].Weight != 1 {
		t.Fatalf("upstreams after rollback: %+v %v", ups, err)
	}
	routes, err := st.ListRoutes(created)
	if err != nil || len(routes) != 1 || routes[0].Match != "/api" || routes[0].Target != "http://10.0.0.5:8080" {
		t.Fatalf("routes after rollback: %+v %v", routes, err)
	}
}
