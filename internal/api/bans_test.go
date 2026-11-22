package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestCreateBanReturnsTheListShape keeps POST /api/bans and GET /api/bans on the
// same JSON contract. The POST handler used to return the ban engine's Go
// struct, whose fields had no tags, so callers saw "CIDR"/"Permanent" while the
// list returned "cidr"/"permanent".
func TestCreateBanReturnsTheListShape(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/bans",
		strings.NewReader(`{"cidr":"203.0.113.9","reason":"test ban","ttl_seconds":3600}`))
	req.Host = "gui.local"
	req.RemoteAddr = "192.168.101.10:5000"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/bans = %d: %s", rec.Code, rec.Body.String())
	}

	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	for _, key := range []string{"id", "cidr", "reason", "source", "permanent", "hits", "created_by", "created_at"} {
		if _, ok := created[key]; !ok {
			t.Fatalf("created ban is missing %q: %s", key, rec.Body.String())
		}
	}
	for _, key := range []string{"CIDR", "Reason", "Permanent", "CreatedAt"} {
		if _, ok := created[key]; ok {
			t.Fatalf("created ban still uses Go field name %q: %s", key, rec.Body.String())
		}
	}
	if created["cidr"] != "203.0.113.9/32" || created["source"] != "manual" || created["created_by"] != "admin" {
		t.Fatalf("unexpected created ban: %v", created)
	}

	// The list must contain the same row with the same id, so a UI that adds the
	// POST response optimistically and then reloads does not see two entries.
	get := httptest.NewRequest(http.MethodGet, "/api/bans", nil)
	get.Host = "gui.local"
	get.RemoteAddr = "192.168.101.10:5000"
	get.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	getRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(getRec, get)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET /api/bans = %d: %s", getRec.Code, getRec.Body.String())
	}
	var list struct {
		Bans []map[string]any `json:"bans"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list %q: %v", getRec.Body.String(), err)
	}
	if len(list.Bans) != 1 {
		t.Fatalf("GET /api/bans returned %d rows, want 1", len(list.Bans))
	}
	if list.Bans[0]["id"] != created["id"] || list.Bans[0]["cidr"] != created["cidr"] {
		t.Fatalf("POST row %v does not match GET row %v", created, list.Bans[0])
	}
}

// Rolling permanent bans up writes one local threat list, keeps them blocked
// through it, and clears them out of the ban table.
func TestRollupMovesPermanentBansIntoALocalFeed(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	srv.cfg.DataDir = t.TempDir()

	makeBan := func(cidr string, permanent bool) {
		body := `{"cidr":"` + cidr + `","reason":"rollup test","permanent":` + map[bool]string{true: "true", false: "false"}[permanent] + `}`
		req := httptest.NewRequest(http.MethodPost, "/api/bans", strings.NewReader(body))
		req.Host = "gui.local"
		req.RemoteAddr = "192.168.101.10:5000"
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		req.Header.Set("X-CSRF-Token", csrf)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("POST /api/bans = %d: %s", rec.Code, rec.Body.String())
		}
	}
	makeBan("203.0.113.50", true)
	makeBan("203.0.113.51", false)

	req := httptest.NewRequest(http.MethodPost, "/api/bans/rollup", nil)
	req.Host = "gui.local"
	req.RemoteAddr = "192.168.101.10:5000"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/bans/rollup = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		RolledUp int    `json:"rolled_up"`
		Path     string `json:"path"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.RolledUp != 1 {
		t.Fatalf("rolled up %d bans, want only the permanent one", out.RolledUp)
	}

	file, err := os.ReadFile(out.Path)
	if err != nil {
		t.Fatalf("the threat list was not written: %v", err)
	}
	if !strings.Contains(string(file), "203.0.113.50/32") || strings.Contains(string(file), "203.0.113.51") {
		t.Fatalf("unexpected threat list contents: %s", file)
	}

	feeds, err := st.ListFeeds()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range feeds {
		if f.Name == permanentFeedName && f.LocalPath == out.Path && f.Action == "block" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no local feed points at the rolled-up list: %+v", feeds)
	}

	bans, err := st.ListBans(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 1 || bans[0].CIDR != "203.0.113.51/32" {
		t.Fatalf("the rolled-up ban is still in the table: %+v", bans)
	}
}
