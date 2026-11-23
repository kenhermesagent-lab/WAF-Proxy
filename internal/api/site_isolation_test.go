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
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/siteres"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// TestConsoleHostSeesOnlyItsSite drives the console the way a browser does, on
// two console hosts served by one process: each request may read and change
// only the rows of the site its Host names.
func TestConsoleHostSeesOnlyItsSite(t *testing.T) {
	srv, st, alphaToken, alphaCSRF := newObservabilityServer(t)
	srv.geo = geoip.Open(t.TempDir())
	// The certificate and policy endpoints read the site's own instances.
	res, err := siteres.New(siteres.Deps{
		Store: st, Box: srv.box, Log: srv.log, Bans: srv.bans, Metrics: srv.metrics,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.res = res

	alphaProxy, err := st.CreateProxy(&model.Proxy{Hostname: "alpha.example.com", Enabled: true, WAFMode: "inherit"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddBan(&model.Ban{CIDR: "203.0.113.10/32", Reason: "alpha", Source: "manual"}); err != nil {
		t.Fatal(err)
	}

	site, err := st.CreateSite("bravo", "Bravo", "console.bravo.test")
	if err != nil {
		t.Fatal(err)
	}
	bravo := st.InSite(site.ID)
	bravoProxy, err := bravo.CreateProxy(&model.Proxy{Hostname: "bravo.example.com", Enabled: true, WAFMode: "inherit"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bravo.AddBan(&model.Ban{CIDR: "198.51.100.7/32", Reason: "bravo", Source: "manual"}); err != nil {
		t.Fatal(err)
	}
	if err := bravo.SetSetting("retention_days", "3"); err != nil {
		t.Fatal(err)
	}
	if err := bravo.InsertEvents([]model.Event{{TS: time.Now(), ProxyID: &bravoProxy,
		Host: "bravo.example.com", Action: "allow", Stage: "route"}}); err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := bravo.CreateUser("bravo-admin", hash, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	bravoToken, _ := wfcrypto.RandomToken(32)
	bravoCSRF, _ := wfcrypto.RandomToken(24)
	if err := bravo.CreateSession(bravoToken, uid, bravoCSRF, "127.0.0.1", "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	call := func(host, method, path, token, csrf, body string) *httptest.ResponseRecorder {
		var reader *strings.Reader
		if body == "" {
			reader = strings.NewReader("")
		} else {
			reader = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, path, reader)
		req.Host = host
		req.RemoteAddr = "127.0.0.1:5000"
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}
	mustJSON := func(rec *httptest.ResponseRecorder, want int) string {
		t.Helper()
		if rec.Code != want {
			t.Fatalf("status = %d, want %d: %s", rec.Code, want, rec.Body.String())
		}
		return rec.Body.String()
	}

	// Reads stay inside the host the request arrived on.
	body := mustJSON(call("console.bravo.test", http.MethodGet, "/api/proxies", bravoToken, "", ""), http.StatusOK)
	if !strings.Contains(body, "bravo.example.com") || strings.Contains(body, "alpha.example.com") {
		t.Fatalf("bravo proxies leaked: %s", body)
	}
	body = mustJSON(call("gui.local", http.MethodGet, "/api/proxies", alphaToken, "", ""), http.StatusOK)
	if !strings.Contains(body, "alpha.example.com") || strings.Contains(body, "bravo.example.com") {
		t.Fatalf("default proxies leaked: %s", body)
	}

	body = mustJSON(call("console.bravo.test", http.MethodGet, "/api/bans?all=1", bravoToken, "", ""), http.StatusOK)
	if !strings.Contains(body, "198.51.100.7") || strings.Contains(body, "203.0.113.10") {
		t.Fatalf("bravo bans leaked: %s", body)
	}
	body = mustJSON(call("gui.local", http.MethodGet, "/api/bans?all=1", alphaToken, "", ""), http.StatusOK)
	if !strings.Contains(body, "203.0.113.10") || strings.Contains(body, "198.51.100.7") {
		t.Fatalf("default bans leaked: %s", body)
	}

	body = mustJSON(call("console.bravo.test", http.MethodGet, "/api/users", bravoToken, "", ""), http.StatusOK)
	if !strings.Contains(body, "bravo-admin") || strings.Contains(body, `"admin"`) {
		t.Fatalf("bravo users leaked: %s", body)
	}

	body = mustJSON(call("console.bravo.test", http.MethodGet, "/api/events", bravoToken, "", ""), http.StatusOK)
	if !strings.Contains(body, "bravo.example.com") || strings.Contains(body, "app.example.com") {
		t.Fatalf("bravo events leaked: %s", body)
	}

	body = mustJSON(call("console.bravo.test", http.MethodGet, "/api/audit", bravoToken, "", ""), http.StatusOK)
	if strings.Contains(body, `"admin"`) {
		t.Fatalf("bravo audit shows default's rows: %s", body)
	}

	// Settings are per site, and the host-wide ones cannot be moved.
	body = mustJSON(call("console.bravo.test", http.MethodGet, "/api/settings", bravoToken, "", ""), http.StatusOK)
	if !strings.Contains(body, `"retention_days":"3"`) {
		t.Fatalf("bravo settings = %s", body)
	}
	mustJSON(call("console.bravo.test", http.MethodPut, "/api/settings", bravoToken, bravoCSRF,
		`{"wan_ip":"203.0.113.99"}`), http.StatusForbidden)
	mustJSON(call("gui.local", http.MethodPut, "/api/settings", alphaToken, alphaCSRF,
		`{"wan_ip":"203.0.113.99"}`), http.StatusOK)
	if got, _ := st.GetSetting("wan_ip"); got != "203.0.113.99" {
		t.Fatalf("default could not set the host address: %q", got)
	}

	// Every other site-scoped domain the console exposes stays inside its
	// site too. A leak in any of these fails here rather than being reasoned
	// about.
	mustJSON(call("console.bravo.test", http.MethodPost, "/api/feeds", bravoToken, bravoCSRF,
		`{"name":"bravo-feed","url":"https://example.com/bravo.txt","action":"block"}`), http.StatusCreated)
	body = mustJSON(call("console.bravo.test", http.MethodGet, "/api/feeds", bravoToken, "", ""), http.StatusOK)
	if !strings.Contains(body, "bravo-feed") {
		t.Fatalf("bravo feeds lost its own row: %s", body)
	}
	body = mustJSON(call("gui.local", http.MethodGet, "/api/feeds", alphaToken, "", ""), http.StatusOK)
	if strings.Contains(body, "bravo-feed") {
		t.Fatalf("bravo feed leaked to the default console: %s", body)
	}

	mustJSON(call("console.bravo.test", http.MethodPost, "/api/lists", bravoToken, bravoCSRF,
		`{"name":"bravo-list","kind":"blocklist","ips":"198.51.100.0/24"}`), http.StatusCreated)
	body = mustJSON(call("console.bravo.test", http.MethodGet, "/api/lists", bravoToken, "", ""), http.StatusOK)
	if !strings.Contains(body, "bravo-list") {
		t.Fatalf("bravo access lists lost its own row: %s", body)
	}
	body = mustJSON(call("gui.local", http.MethodGet, "/api/lists", alphaToken, "", ""), http.StatusOK)
	if strings.Contains(body, "bravo-list") {
		t.Fatalf("bravo access list leaked to the default console: %s", body)
	}

	mustJSON(call("console.bravo.test", http.MethodPost, "/api/profiles", bravoToken, bravoCSRF,
		`{"name":"bravo-waf"}`), http.StatusCreated)
	body = mustJSON(call("console.bravo.test", http.MethodGet, "/api/profiles", bravoToken, "", ""), http.StatusOK)
	if !strings.Contains(body, "bravo-waf") {
		t.Fatalf("bravo WAF profiles lost its own row: %s", body)
	}
	body = mustJSON(call("gui.local", http.MethodGet, "/api/profiles", alphaToken, "", ""), http.StatusOK)
	if strings.Contains(body, "bravo-waf") {
		t.Fatalf("bravo WAF profile leaked to the default console: %s", body)
	}

	mustJSON(call("console.bravo.test", http.MethodPost, "/api/protection-profiles", bravoToken, bravoCSRF,
		`{"name":"bravo-protection"}`), http.StatusCreated)
	body = mustJSON(call("console.bravo.test", http.MethodGet, "/api/protection-profiles", bravoToken, "", ""), http.StatusOK)
	if !strings.Contains(body, "bravo-protection") {
		t.Fatalf("bravo protection profiles lost its own row: %s", body)
	}
	body = mustJSON(call("gui.local", http.MethodGet, "/api/protection-profiles", alphaToken, "", ""), http.StatusOK)
	if strings.Contains(body, "bravo-protection") {
		t.Fatalf("bravo protection profile leaked to the default console: %s", body)
	}

	if _, err := bravo.SaveCert(&model.Cert{Domains: "bravo.example.com", Status: "issued", Source: model.CertSourceUploaded}); err != nil {
		t.Fatal(err)
	}
	body = mustJSON(call("console.bravo.test", http.MethodGet, "/api/certs", bravoToken, "", ""), http.StatusOK)
	if !strings.Contains(body, "bravo.example.com") {
		t.Fatalf("bravo certificates lost its own row: %s", body)
	}
	body = mustJSON(call("gui.local", http.MethodGet, "/api/certs", alphaToken, "", ""), http.StatusOK)
	if strings.Contains(body, "bravo.example.com") {
		t.Fatalf("bravo certificate leaked to the default console: %s", body)
	}

	mustJSON(call("console.bravo.test", http.MethodPut, "/api/log-views/bravo-view", bravoToken, bravoCSRF,
		`{"query":"host:bravo.example.com"}`), http.StatusOK)
	body = mustJSON(call("console.bravo.test", http.MethodGet, "/api/log-views", bravoToken, "", ""), http.StatusOK)
	if !strings.Contains(body, "bravo-view") {
		t.Fatalf("bravo saved views lost its own row: %s", body)
	}
	body = mustJSON(call("gui.local", http.MethodGet, "/api/log-views", alphaToken, "", ""), http.StatusOK)
	if strings.Contains(body, "bravo-view") {
		t.Fatalf("bravo saved view leaked to the default console: %s", body)
	}

	// Writes cannot reach the other site, even by row id.
	if rec := call("console.bravo.test", http.MethodDelete, "/api/proxies/"+itoa(alphaProxy), bravoToken, bravoCSRF, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("bravo deleted the default site's proxy: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := st.GetProxy(alphaProxy); err != nil {
		t.Fatalf("the default site's proxy is gone: %v", err)
	}
	if rec := call("gui.local", http.MethodDelete, "/api/proxies/"+itoa(bravoProxy), alphaToken, alphaCSRF, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("default deleted bravo's proxy: %d %s", rec.Code, rec.Body.String())
	}

	// A session belongs to the console that issued it.
	if rec := call("gui.local", http.MethodGet, "/api/me", bravoToken, "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bravo session authenticated on the default console: %d", rec.Code)
	}

	// The login form on a site's console only accepts that site's admins.
	login := func(host, user, password string) int {
		payload, _ := json.Marshal(map[string]string{"username": user, "password": password})
		req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(string(payload)))
		req.Host = host
		req.RemoteAddr = "127.0.0.1:5001"
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	if code := login("console.bravo.test", "admin", "a sufficiently long password"); code != http.StatusUnauthorized {
		t.Fatalf("default admin signed in on bravo's console: %d", code)
	}
	if code := login("console.bravo.test", "bravo-admin", "a sufficiently long password"); code != http.StatusOK {
		t.Fatalf("bravo admin could not sign in on its own console: %d", code)
	}
	if code := login("gui.local", "admin", "a sufficiently long password"); code != http.StatusOK {
		t.Fatalf("default admin could not sign in on its own console: %d", code)
	}
}

func itoa(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// TestBackupAndRestoreStayInsideOneSite proves a backup is one site's
// configuration and a restore writes only into the console it was posted to.
func TestBackupAndRestoreStayInsideOneSite(t *testing.T) {
	srv, st, alphaToken, _ := newObservabilityServer(t)
	srv.geo = geoip.Open(t.TempDir())
	if _, err := st.CreateProxy(&model.Proxy{Hostname: "alpha.example.com", Enabled: true, WAFMode: "inherit"}); err != nil {
		t.Fatal(err)
	}

	addSite := func(slug, host, user string) (*model.Site, *store.Store, string, string) {
		t.Helper()
		site, err := st.CreateSite(slug, slug, host)
		if err != nil {
			t.Fatal(err)
		}
		scoped := st.InSite(site.ID)
		hash, err := auth.HashPassword("a sufficiently long password")
		if err != nil {
			t.Fatal(err)
		}
		uid, err := scoped.CreateUser(user, hash, "", "", false)
		if err != nil {
			t.Fatal(err)
		}
		token, _ := wfcrypto.RandomToken(32)
		csrf, _ := wfcrypto.RandomToken(24)
		if err := scoped.CreateSession(token, uid, csrf, "127.0.0.1", "test", time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		return site, scoped, token, csrf
	}
	_, bravo, _, _ := addSite("bravo", "console.bravo.test", "bravo-admin")
	_, charlie, charlieToken, charlieCSRF := addSite("charlie", "console.charlie.test", "charlie-admin")
	if _, err := bravo.CreateProxy(&model.Proxy{Hostname: "bravo.example.com", Enabled: true, WAFMode: "inherit"}); err != nil {
		t.Fatal(err)
	}

	call := func(host, method, path, token, csrf string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(string(body)))
		req.Host = host
		req.RemoteAddr = "127.0.0.1:5000"
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	// The default console's backup covers the default site only.
	rec := call("gui.local", http.MethodGet, "/api/backup", alphaToken, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("backup download = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "bravo.example.com") {
		t.Fatalf("the default site's backup contains another site's proxy: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "alpha.example.com") {
		t.Fatalf("the default site's backup lost its own proxy: %s", rec.Body.String())
	}
	if got := rec.Header().Get("Content-Disposition"); !strings.Contains(got, "wafproxy-default-backup.json") {
		t.Fatalf("backup file name = %q", got)
	}

	// A site's backup restores into another site and nowhere else. The source
	// hostname is released first, because one hostname belongs to one site.
	_, delta, deltaToken, _ := addSite("delta", "console.delta.test", "delta-admin")
	pid, err := delta.CreateProxy(&model.Proxy{Hostname: "delta.example.com", Enabled: true, WAFMode: "inherit"})
	if err != nil {
		t.Fatal(err)
	}
	rec = call("console.delta.test", http.MethodGet, "/api/backup", deltaToken, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("delta backup = %d", rec.Code)
	}
	doc := rec.Body.Bytes()
	if err := delta.DeleteProxy(pid); err != nil {
		t.Fatal(err)
	}
	if rec := call("console.charlie.test", http.MethodPost, "/api/backup/restore", charlieToken, charlieCSRF, doc); rec.Code != http.StatusOK {
		t.Fatalf("restore into charlie = %d: %s", rec.Code, rec.Body.String())
	}
	if list, _ := charlie.ListProxies(); len(list) != 1 || list[0].Hostname != "delta.example.com" {
		t.Fatalf("charlie did not receive the restore: %+v", list)
	}
	if list, _ := bravo.ListProxies(); len(list) != 1 || list[0].Hostname != "bravo.example.com" {
		t.Fatalf("restore changed bravo: %+v", list)
	}
	if list, _ := st.ListProxies(); len(list) != 1 || list[0].Hostname != "alpha.example.com" {
		t.Fatalf("restore changed the default site: %+v", list)
	}
}
