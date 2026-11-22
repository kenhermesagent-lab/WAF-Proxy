package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/intel"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
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
	srv.feeds = intel.New(st, slog.New(slog.NewTextHandler(io.Discard, nil)), 0)

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
			if !f.AlwaysBlock {
				t.Fatalf("the rolled-up list is not enforced ahead of the allow lists: %+v", f)
			}
			if f.State != "ok" || f.LastCount != 1 {
				t.Fatalf("the rolled-up list did not load before the bans were removed: %+v", f)
			}
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

// TestRollupKeepsBansWhenTheListCannotLoad proves the fail-safe: with no feed
// engine to load the list, nothing is deleted and the request fails loudly.
func TestRollupKeepsBansWhenTheListCannotLoad(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	srv.cfg.DataDir = t.TempDir()

	req := httptest.NewRequest(http.MethodPost, "/api/bans",
		strings.NewReader(`{"cidr":"203.0.113.60","reason":"fail-safe test","permanent":true}`))
	req.Host = "gui.local"
	req.RemoteAddr = "192.168.101.10:5000"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/bans = %d: %s", rec.Code, rec.Body.String())
	}

	roll := httptest.NewRequest(http.MethodPost, "/api/bans/rollup", nil)
	roll.Host = "gui.local"
	roll.RemoteAddr = "192.168.101.10:5000"
	roll.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	roll.Header.Set("X-CSRF-Token", csrf)
	rollRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rollRec, roll)
	if rollRec.Code == http.StatusOK {
		t.Fatalf("rollup succeeded without a loaded list: %s", rollRec.Body.String())
	}

	bans, err := st.ListBans(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 1 || bans[0].CIDR != "203.0.113.60/32" {
		t.Fatalf("the ban was dropped without the list being loaded: %+v", bans)
	}
}

// TestBanListTruncationFlagMatchesTheAppliedLimit covers the note in the ban
// view: the flag must describe the limit the store actually applied, including
// the default, rather than only an explicitly passed one.
func TestBanListTruncationFlagMatchesTheAppliedLimit(t *testing.T) {
	srv, st, token, _ := newObservabilityServer(t)
	for i := 0; i < 200; i++ {
		cidr := fmt.Sprintf("198.51.%d.%d/32", i/250, i%250+1)
		if _, err := st.AddBan(&model.Ban{CIDR: cidr, Reason: "fill", Source: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	get := func(query string) (int, bool) {
		req := httptest.NewRequest(http.MethodGet, "/api/bans"+query, nil)
		req.Host = "gui.local"
		req.RemoteAddr = "192.168.101.10:5000"
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/bans%s = %d: %s", query, rec.Code, rec.Body.String())
		}
		var out struct {
			Bans    []map[string]any `json:"bans"`
			Limited bool             `json:"limited"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return len(out.Bans), out.Limited
	}

	if n, limited := get(""); n != 200 || !limited {
		t.Fatalf("default limit returned %d rows, limited=%v; want a truncated list", n, limited)
	}
	if n, limited := get("?limit=50"); n != 50 || !limited {
		t.Fatalf("explicit limit returned %d rows, limited=%v", n, limited)
	}
	if n, limited := get("?limit=1000"); n != 200 || limited {
		t.Fatalf("a limit above the table size reported %d rows, limited=%v", n, limited)
	}
}
