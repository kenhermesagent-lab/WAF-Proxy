package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/rbac"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// sitesCall drives the console API as one signed-in administrator, optionally
// asking for another site the way the switcher does.
func sitesCall(srv *Server, host, method, path, token, csrf, site string, body any) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body == nil {
		reader = strings.NewReader("")
	} else {
		raw, _ := json.Marshal(body)
		reader = strings.NewReader(string(raw))
	}
	req := httptest.NewRequest(method, path, reader)
	req.Host = host
	req.RemoteAddr = "127.0.0.1:5000"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	if site != "" {
		req.Header.Set("X-WAF-Site", site)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestSitesAPIListsAndManagesSites(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if _, err := st.CreateProxy(&model.Proxy{Hostname: "alpha.example.com", Enabled: true, WAFMode: "inherit"}); err != nil {
		t.Fatal(err)
	}

	var rows []siteRow
	if rec := sitesCall(srv, "gui.local", http.MethodGet, "/api/sites", token, "", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("list sites = %d: %s", rec.Code, rec.Body.String())
	} else if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Slug != store.DefaultSiteSlug || !rows[0].Current {
		t.Fatalf("unexpected sites list: %+v", rows)
	}
	if len(rows[0].Hostnames) != 1 || rows[0].Hostnames[0] != "alpha.example.com" {
		t.Fatalf("the default site's hostnames are wrong: %+v", rows[0].Hostnames)
	}

	// A form mistake is refused with a message, not a 500.
	if rec := sitesCall(srv, "gui.local", http.MethodPost, "/api/sites", token, csrf, "", map[string]string{"slug": "Bad Slug"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid slug = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := sitesCall(srv, "gui.local", http.MethodPost, "/api/sites", token, csrf, "", map[string]string{"slug": "bravo", "console_host": "https://console.bravo.test"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid console host = %d: %s", rec.Code, rec.Body.String())
	}

	rec := sitesCall(srv, "gui.local", http.MethodPost, "/api/sites", token, csrf, "", map[string]string{
		"slug": "bravo", "name": "Bravo", "console_host": "console.bravo.test",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create site = %d: %s", rec.Code, rec.Body.String())
	}
	var bravo siteRow
	if err := json.Unmarshal(rec.Body.Bytes(), &bravo); err != nil {
		t.Fatal(err)
	}
	if bravo.Slug != "bravo" || bravo.ConsoleHost != "console.bravo.test" || !bravo.Enabled {
		t.Fatalf("created site is wrong: %+v", bravo)
	}

	// The same slug, and the same console host under a new slug, are conflicts
	// the form can explain.
	for _, dup := range []map[string]string{
		{"slug": "bravo", "console_host": "console.charlie.test"},
		{"slug": "charlie", "console_host": "console.bravo.test"},
	} {
		if rec := sitesCall(srv, "gui.local", http.MethodPost, "/api/sites", token, csrf, "", dup); rec.Code != http.StatusConflict {
			t.Fatalf("duplicate %v = %d: %s", dup, rec.Code, rec.Body.String())
		}
	}

	if rec := sitesCall(srv, "gui.local", http.MethodPut, "/api/sites/bravo", token, csrf, "", map[string]any{
		"name": "Bravo Two", "enabled": false,
	}); rec.Code != http.StatusOK {
		t.Fatalf("update site = %d: %s", rec.Code, rec.Body.String())
	}
	if site, err := st.SiteBySlug("bravo"); err != nil || site.Name != "Bravo Two" || site.Enabled {
		t.Fatalf("update did not stick: %+v %v", site, err)
	}

	// The default site owns the console and cannot be removed or disabled.
	if rec := sitesCall(srv, "gui.local", http.MethodDelete, "/api/sites/"+store.DefaultSiteSlug, token, csrf, "", nil); rec.Code != http.StatusConflict {
		t.Fatalf("delete default = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := sitesCall(srv, "gui.local", http.MethodPut, "/api/sites/"+store.DefaultSiteSlug, token, csrf, "", map[string]any{"enabled": false}); rec.Code != http.StatusConflict {
		t.Fatalf("disable default = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := sitesCall(srv, "gui.local", http.MethodDelete, "/api/sites/bravo", token, csrf, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("delete bravo = %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := st.SiteBySlug("bravo"); err == nil {
		t.Fatal("the deleted site is still there")
	}
}

// TestHostAdminStaysOnItsOwnSite proves the UI's restriction is enforced: a
// host administrator cannot list sites, and its site header is ignored.
func TestHostAdminStaysOnItsOwnSite(t *testing.T) {
	srv, st, adminToken, _ := newObservabilityServer(t)
	if _, err := st.CreateProxy(&model.Proxy{Hostname: "alpha.example.com", Enabled: true, WAFMode: "inherit"}); err != nil {
		t.Fatal(err)
	}
	site, err := st.CreateSite("bravo", "Bravo", "console.bravo.test")
	if err != nil {
		t.Fatal(err)
	}
	bravo := st.InSite(site.ID)
	if _, err := bravo.CreateProxy(&model.Proxy{Hostname: "bravo.example.com", Enabled: true, WAFMode: "inherit"}); err != nil {
		t.Fatal(err)
	}
	var roleID int64
	roles, err := bravo.ListRoles()
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range roles {
		if role.Name == rbac.HostAdmin {
			roleID = role.ID
		}
	}
	if roleID == 0 {
		t.Fatal("the host_admin role was not seeded")
	}
	hash, err := auth.HashPassword("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := bravo.CreateUser("bravo-admin", hash, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := bravo.UpdateUserRole(uid, roleID); err != nil {
		t.Fatal(err)
	}
	token, _ := wfcrypto.RandomToken(32)
	csrf, _ := wfcrypto.RandomToken(24)
	if err := bravo.CreateSession(token, uid, csrf, "127.0.0.1", "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	// The sites area is not part of the role, so the page cannot even list.
	if rec := sitesCall(srv, "console.bravo.test", http.MethodGet, "/api/sites", token, "", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("host_admin listed sites: %d", rec.Code)
	}

	// A switcher header for the default site is ignored, not obeyed.
	rec := sitesCall(srv, "console.bravo.test", http.MethodGet, "/api/proxies", token, "", store.DefaultSiteSlug, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("host_admin proxy list = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "alpha.example.com") {
		t.Fatalf("host_admin reached another site: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "bravo.example.com") {
		t.Fatalf("host_admin lost its own proxies: %s", rec.Body.String())
	}

	// /api/me names the site and withdraws the switcher.
	var me struct {
		Site      string              `json:"site"`
		SiteName  string              `json:"site_name"`
		CanSwitch bool                `json:"can_switch"`
		Sites     []map[string]string `json:"sites"`
	}
	rec = sitesCall(srv, "console.bravo.test", http.MethodGet, "/api/me", token, "", "", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me.Site != "bravo" || me.SiteName != "Bravo" || me.CanSwitch || len(me.Sites) != 0 {
		t.Fatalf("host_admin /api/me = %+v", me)
	}

	// A host administrator may switch, and is told what it may switch to.
	rec = sitesCall(srv, "gui.local", http.MethodGet, "/api/me", adminToken, "", "", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me.Site != store.DefaultSiteSlug || !me.CanSwitch || len(me.Sites) != 2 {
		t.Fatalf("administrator /api/me = %+v", me)
	}

	// The switcher really scopes: the same request with the header sees bravo.
	rec = sitesCall(srv, "gui.local", http.MethodGet, "/api/proxies", adminToken, "", "bravo", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("switched proxy list = %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "bravo.example.com") || strings.Contains(rec.Body.String(), "alpha.example.com") {
		t.Fatalf("the switch did not scope the request: %s", rec.Body.String())
	}
}
