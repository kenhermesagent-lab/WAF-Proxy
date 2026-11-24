package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/canary"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/rbac"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/siteres"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// recordingProbe remembers which host each canary probe asked for, so a test
// can prove the probe came from the right site's monitor.
type recordingProbe struct {
	mu    sync.Mutex
	hosts []string
}

func (p *recordingProbe) Run(_ context.Context, host string) canary.Result {
	p.mu.Lock()
	p.hosts = append(p.hosts, host)
	p.mu.Unlock()
	return canary.Result{OK: true, Host: host}
}

func (p *recordingProbe) last() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.hosts) == 0 {
		return ""
	}
	return p.hosts[len(p.hosts)-1]
}

// siteFixtures builds a server whose five resources are per site, a second site,
// and a host_admin session inside it.
type siteFixtures struct {
	srv   *Server
	st    *store.Store
	res   *siteres.Set
	probe *recordingProbe

	adminToken, adminCSRF string
	bravo                 *model.Site
	bravoToken, bravoCSRF string
	hostToken, hostCSRF   string
}

func newSiteFixtures(t *testing.T) *siteFixtures {
	t.Helper()
	srv, st, token, csrf := newObservabilityServer(t)
	probe := &recordingProbe{}
	res, err := siteres.New(siteres.Deps{
		Store: st, Box: srv.box, Log: srv.log, Bans: srv.bans,
		Metrics: srv.metrics, Prober: probe,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.res = res

	bravo, err := st.CreateSite("bravo", "Bravo", "console.bravo.test")
	if err != nil {
		t.Fatal(err)
	}
	scoped := st.InSite(bravo.ID)
	hash, err := auth.HashPassword("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	var adminRole, hostRole int64
	roles, err := scoped.ListRoles()
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range roles {
		switch role.Name {
		case rbac.Administrator:
			adminRole = role.ID
		case rbac.HostAdmin:
			hostRole = role.ID
		}
	}
	issue := func(name string, roleID int64) (string, string) {
		t.Helper()
		uid, err := scoped.CreateUserWithRole(name, hash, "", "", false, roleID)
		if err != nil {
			t.Fatal(err)
		}
		session, _ := wfcrypto.RandomToken(32)
		sessionCSRF, _ := wfcrypto.RandomToken(24)
		if err := scoped.CreateSession(session, uid, sessionCSRF, "127.0.0.1", "test", time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		return session, sessionCSRF
	}
	bravoToken, bravoCSRF := issue("bravo-admin", adminRole)
	hostToken, hostCSRF := issue("bravo-tenant", hostRole)

	return &siteFixtures{
		srv: srv, st: st, res: res, probe: probe,
		adminToken: token, adminCSRF: csrf,
		bravo: bravo, bravoToken: bravoToken, bravoCSRF: bravoCSRF,
		hostToken: hostToken, hostCSRF: hostCSRF,
	}
}

func (f *siteFixtures) call(host, method, path, token, csrf, site string, body any) *httptest.ResponseRecorder {
	return sitesCall(f.srv, host, method, path, token, csrf, site, body)
}

// TestPerSiteResourcesAreIsolated drives the five resources through the API:
// a write on one site's console is invisible on the other, and the default
// site keeps the configuration it had.
func TestPerSiteResourcesAreIsolated(t *testing.T) {
	f := newSiteFixtures(t)
	st := f.st

	// --- policy settings: max_body is one process-wide buffer ---
	if rec := f.call("gui.local", http.MethodPut, "/api/settings", f.adminToken, f.adminCSRF, "", map[string]string{"max_body": "8192"}); rec.Code != http.StatusOK {
		t.Fatalf("default settings = %d: %s", rec.Code, rec.Body.String())
	}
	// A non-default console may not move the buffer every site's traffic uses.
	rec := f.call("console.bravo.test", http.MethodPut, "/api/settings", f.bravoToken, f.bravoCSRF, "", map[string]string{"max_body": "2048"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bravo max_body write = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), store.ErrHostWideSetting.Error()) {
		t.Fatalf("bravo max_body refusal = %s", rec.Body.String())
	}
	bravoRes, err := f.res.For(f.bravo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := bravoRes.Policy.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := bravoRes.Policy.CurrentSettings().MaxBody; got != 8192 {
		t.Fatalf("bravo policy max body = %d, want the host's 8192", got)
	}
	if got := f.res.Default().Policy.CurrentSettings().MaxBody; got != 8192 {
		t.Fatalf("default policy max body = %d, want 8192", got)
	}
	if got, err := f.st.InSite(f.bravo.ID).GetSetting("max_body"); err != nil || got != "8192" {
		t.Fatalf("bravo reads max_body %q (%v), want the host's 8192", got, err)
	}
	// The refusal is specific to host-wide keys: the same console still saves
	// its own settings.
	if rec := f.call("console.bravo.test", http.MethodPut, "/api/settings", f.bravoToken, f.bravoCSRF, "", map[string]string{"retention_days": "5"}); rec.Code != http.StatusOK {
		t.Fatalf("bravo retention write = %d: %s", rec.Code, rec.Body.String())
	}
	router := siteres.NewRouter(f.res)
	if got := router.Settings(f.bravo.ID).MaxBody; got != 8192 {
		t.Fatalf("router answered %d for bravo, want the host's 8192", got)
	}

	// --- notification channels ---
	if rec := f.call("console.bravo.test", http.MethodPut, "/api/notifications", f.bravoToken, f.bravoCSRF, "", map[string]string{
		"smtp_host": "smtp.bravo.test", "telegram_chat": "bravo-chat", "events": "ban,gate",
	}); rec.Code != http.StatusOK {
		t.Fatalf("bravo notifications = %d: %s", rec.Code, rec.Body.String())
	}
	type notifyBody struct {
		Settings map[string]string `json:"settings"`
	}
	readNotifications := func(host, token string) notifyBody {
		t.Helper()
		rec := f.call(host, http.MethodGet, "/api/notifications", token, "", "", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s notification read = %d: %s", host, rec.Code, rec.Body.String())
		}
		var body notifyBody
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	bravoNotify := readNotifications("console.bravo.test", f.bravoToken)
	defaultNotify := readNotifications("gui.local", f.adminToken)
	if bravoNotify.Settings["smtp_host"] != "smtp.bravo.test" || bravoNotify.Settings["telegram_chat"] != "@bravo-chat" {
		t.Fatalf("bravo channels = %+v", bravoNotify.Settings)
	}
	if defaultNotify.Settings["smtp_host"] != "" || defaultNotify.Settings["telegram_chat"] != "" {
		t.Fatalf("the default site's channels changed: %+v", defaultNotify.Settings)
	}

	// --- anomaly thresholds ---
	readAnomaly := func(host, token string) struct {
		Config struct {
			Enabled  bool `json:"enabled"`
			EgressMB int  `json:"egress_mb"`
		} `json:"config"`
	} {
		t.Helper()
		rec := f.call(host, http.MethodGet, "/api/anomaly", token, "", "", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s anomaly read = %d: %s", host, rec.Code, rec.Body.String())
		}
		var body struct {
			Config struct {
				Enabled  bool `json:"enabled"`
				EgressMB int  `json:"egress_mb"`
			} `json:"config"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	defaultBefore := readAnomaly("gui.local", f.adminToken)
	if rec := f.call("console.bravo.test", http.MethodPut, "/api/anomaly/settings", f.bravoToken, f.bravoCSRF, "", map[string]any{
		"enabled": true, "egress_mb": 11, "egress_factor": 3, "rate_rps": 7, "rate_factor": 2, "auth_burst": 4,
	}); rec.Code != http.StatusOK {
		t.Fatalf("bravo anomaly = %d: %s", rec.Code, rec.Body.String())
	}
	bravoAnomaly := readAnomaly("console.bravo.test", f.bravoToken)
	defaultAfter := readAnomaly("gui.local", f.adminToken)
	if !bravoAnomaly.Config.Enabled || bravoAnomaly.Config.EgressMB != 11 {
		t.Fatalf("bravo anomaly config = %+v", bravoAnomaly.Config)
	}
	if defaultAfter != defaultBefore {
		t.Fatalf("the default site's anomaly config changed: %+v -> %+v", defaultBefore, defaultAfter)
	}

	// --- canary: the manual probe runs through the active site's monitor ---
	if err := st.SetSettingsFor(f.bravo.ID, map[string]string{"canary_host": "bravo.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSettings(map[string]string{"canary_host": "alpha.example.com"}); err != nil {
		t.Fatal(err)
	}
	if rec := f.call("console.bravo.test", http.MethodPost, "/api/canary", f.bravoToken, f.bravoCSRF, "", map[string]string{"host": "bravo.example.com"}); rec.Code != http.StatusOK {
		t.Fatalf("bravo canary = %d: %s", rec.Code, rec.Body.String())
	}
	if got := f.probe.last(); got != "bravo.example.com" {
		t.Fatalf("canary probed %q, want bravo.example.com", got)
	}

	// --- ACME: a certificate belongs to the site that stored it ---
	bravoCert := &model.Cert{Domains: "bravo.example.com", Status: "issued", Source: model.CertSourceUploaded}
	if _, err := st.InSite(f.bravo.ID).SaveCert(bravoCert); err != nil {
		t.Fatal(err)
	}
	bravoList, err := st.InSite(f.bravo.ID).ListCerts()
	if err != nil || len(bravoList) != 1 {
		t.Fatalf("bravo certificates = %d (%v)", len(bravoList), err)
	}
	var defaultCerts struct {
		Certs []map[string]any `json:"certs"`
	}
	if rec := f.call("gui.local", http.MethodGet, "/api/certs", f.adminToken, "", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("default certs = %d", rec.Code)
	} else if err := json.Unmarshal(rec.Body.Bytes(), &defaultCerts); err != nil {
		t.Fatal(err)
	}
	if len(defaultCerts.Certs) != 0 {
		t.Fatalf("another site's certificate is visible on the default console: %+v", defaultCerts.Certs)
	}
	if _, err := f.res.For(f.bravo.ID); err != nil {
		t.Fatal(err)
	}
}

// TestTenantAdministratorStaysOnItsConsole proves the wildcard role does not
// lift a tenant session out of its site: the switch header is ignored, the
// host-wide routes stay closed, and role definitions cannot be edited.
func TestTenantAdministratorStaysOnItsConsole(t *testing.T) {
	f := newSiteFixtures(t)
	if rec := f.call("gui.local", http.MethodPut, "/api/notifications", f.adminToken, f.adminCSRF, "", map[string]string{"smtp_host": "smtp.alpha.test"}); rec.Code != http.StatusOK {
		t.Fatalf("default notifications = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := f.call("console.bravo.test", http.MethodPut, "/api/notifications", f.bravoToken, f.bravoCSRF, "", map[string]string{"smtp_host": "smtp.bravo.test"}); rec.Code != http.StatusOK {
		t.Fatalf("bravo notifications = %d: %s", rec.Code, rec.Body.String())
	}

	// The header names the host site, but this session stays on bravo.
	var wrapped struct {
		Settings map[string]string `json:"settings"`
	}
	rec := f.call("console.bravo.test", http.MethodGet, "/api/notifications", f.bravoToken, "", store.DefaultSiteSlug, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("bravo notifications = %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &wrapped); err != nil {
		t.Fatal(err)
	}
	if wrapped.Settings["smtp_host"] != "smtp.bravo.test" {
		t.Fatalf("a tenant administrator switched sites: %+v", wrapped.Settings)
	}

	for _, path := range []string{"/api/sites", "/api/ha", "/api/updates", "/api/backup/schedule"} {
		if rec := f.call("console.bravo.test", http.MethodGet, path, f.bravoToken, "", "", nil); rec.Code != http.StatusForbidden {
			t.Fatalf("tenant GET %s = %d, want 403: %s", path, rec.Code, rec.Body.String())
		}
	}
	if rec := f.call("console.bravo.test", http.MethodPost, "/api/roles", f.bravoToken, f.bravoCSRF, "", map[string]any{
		"name": "tenant-owner", "permissions": []string{"*"},
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("tenant role write = %d, want 403: %s", rec.Code, rec.Body.String())
	}

	var me struct {
		CanSwitch bool   `json:"can_switch"`
		Sites     []any  `json:"sites"`
		Site      string `json:"site"`
	}
	rec = f.call("console.bravo.test", http.MethodGet, "/api/me", f.bravoToken, "", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant me = %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me.CanSwitch || len(me.Sites) != 0 || me.Site != "bravo" {
		t.Fatalf("tenant me advertised the switcher: %+v", me)
	}
}

// TestHostAdminIsConfinedToItsOwnResources sends a site switch header with a
// host_admin session: the API must keep answering from its own site.
func TestHostAdminIsConfinedToItsOwnResources(t *testing.T) {
	f := newSiteFixtures(t)
	if err := f.st.SetSettingsFor(f.bravo.ID, map[string]string{"canary_host": "bravo.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetSettings(map[string]string{"canary_host": "alpha.example.com"}); err != nil {
		t.Fatal(err)
	}
	if rec := f.call("console.bravo.test", http.MethodPut, "/api/notifications", f.bravoToken, f.bravoCSRF, "", map[string]string{"smtp_host": "smtp.bravo.test"}); rec.Code != http.StatusOK {
		t.Fatalf("bravo notifications = %d: %s", rec.Code, rec.Body.String())
	}

	// The header asks for the default site; the session may not follow it.
	if rec := f.call("console.bravo.test", http.MethodPost, "/api/canary", f.hostToken, f.hostCSRF, store.DefaultSiteSlug, map[string]string{"host": "bravo.example.com"}); rec.Code != http.StatusOK {
		t.Fatalf("host_admin canary = %d: %s", rec.Code, rec.Body.String())
	}
	var wrapped struct {
		Settings map[string]string `json:"settings"`
	}
	rec := f.call("console.bravo.test", http.MethodGet, "/api/notifications", f.hostToken, "", store.DefaultSiteSlug, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("host_admin notifications = %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &wrapped); err != nil {
		t.Fatal(err)
	}
	if wrapped.Settings["smtp_host"] != "smtp.bravo.test" {
		t.Fatalf("host_admin read another site's channels: %+v", wrapped.Settings)
	}

	// Its own console is still fully usable.
	if rec := f.call("console.bravo.test", http.MethodPut, "/api/anomaly/settings", f.hostToken, f.hostCSRF, "", map[string]any{
		"enabled": true, "egress_mb": 5, "egress_factor": 2, "rate_rps": 5, "rate_factor": 2, "auth_burst": 3,
	}); rec.Code != http.StatusOK {
		t.Fatalf("host_admin anomaly write = %d: %s", rec.Code, rec.Body.String())
	}
}
