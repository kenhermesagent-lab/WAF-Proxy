package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	// --- policy settings (max body drives the compiled policy) ---
	if rec := f.call("gui.local", http.MethodPut, "/api/settings", f.adminToken, f.adminCSRF, "", map[string]string{"max_body": "8192"}); rec.Code != http.StatusOK {
		t.Fatalf("default settings = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := f.call("console.bravo.test", http.MethodPut, "/api/settings", f.bravoToken, f.bravoCSRF, "", map[string]string{"max_body": "2048"}); rec.Code != http.StatusOK {
		t.Fatalf("bravo settings = %d: %s", rec.Code, rec.Body.String())
	}
	bravoRes, err := f.res.For(f.bravo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := bravoRes.Policy.CurrentSettings().MaxBody; got != 2048 {
		t.Fatalf("bravo policy max body = %d, want 2048", got)
	}
	if got := f.res.Default().Policy.CurrentSettings().MaxBody; got != 8192 {
		t.Fatalf("default policy picked up another site's max body: %d", got)
	}
	// The proxy asks the router, which must answer for the proxy's own site.
	router := siteres.NewRouter(f.res)
	if got := router.Settings(f.bravo.ID).MaxBody; got != 2048 {
		t.Fatalf("router answered %d for bravo", got)
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
