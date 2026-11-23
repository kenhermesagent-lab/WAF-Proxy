package store

import (
	"errors"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// TestScopedStoreCannotSeeAnotherSite is the isolation contract: a handle for
// one site reads and writes only that site's rows, while the default site's
// handle keeps seeing exactly what it saw before sites existed.
func TestScopedStoreCannotSeeAnotherSite(t *testing.T) {
	alpha := openTempStore(t)
	bravo, err := alpha.CreateSite("bravo", "Bravo", "console.bravo.example")
	if err != nil {
		t.Fatalf("create site: %v", err)
	}
	beta := alpha.InSite(bravo.ID)

	// One proxy, ban, user, event, audit row and setting on each side.
	alphaProxy := testProxy(t, alpha, "alpha.example.com")
	betaProxy := testProxy(t, beta, "beta.example.com")

	cidr := "198.51.100.0/24"
	if _, err := alpha.AddBan(&model.Ban{CIDR: cidr, Reason: "alpha", Source: "manual"}); err != nil {
		t.Fatal(err)
	}
	if _, err := beta.AddBan(&model.Ban{CIDR: cidr, Reason: "beta", Source: "manual"}); err != nil {
		t.Fatalf("the same CIDR must be bannable on a second site: %v", err)
	}

	if _, err := beta.CreateUser("ops", "hash", "", "", false); err != nil {
		t.Fatal(err)
	}
	if err := beta.CreateInvite("invite-digest", "new@example.com", "New", "Admin", beta.AdminRoleID(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, ok := alpha.InviteByToken("invite-digest"); ok {
		t.Fatal("alpha resolved beta's invitation")
	}
	if _, ok := beta.InviteByToken("invite-digest"); !ok {
		t.Fatal("beta cannot resolve its own invitation")
	}

	if err := alpha.InsertEvents([]model.Event{{TS: time.Now(), ProxyID: &alphaProxy, Host: "alpha.example.com", Action: "allow", Stage: "route"}}); err != nil {
		t.Fatal(err)
	}
	if err := beta.InsertEvents([]model.Event{{TS: time.Now(), ProxyID: &betaProxy, Host: "beta.example.com", Action: "allow", Stage: "route"}}); err != nil {
		t.Fatal(err)
	}

	alpha.AddAudit("admin", "login", "", "127.0.0.1")
	beta.AddAudit("ops", "login", "", "127.0.0.1")

	if err := beta.SetSetting("retention_days", "3"); err != nil {
		t.Fatal(err)
	}

	// Reads stay on their own side.
	proxies, err := alpha.ListProxies()
	if err != nil || len(proxies) != 1 || proxies[0].Hostname != "alpha.example.com" {
		t.Fatalf("alpha proxies = %+v (%v)", proxies, err)
	}
	proxies, err = beta.ListProxies()
	if err != nil || len(proxies) != 1 || proxies[0].Hostname != "beta.example.com" {
		t.Fatalf("beta proxies = %+v (%v)", proxies, err)
	}
	if _, err := beta.GetProxy(alphaProxy); !errors.Is(err, ErrNotFound) {
		t.Fatalf("beta read alpha's proxy: %v", err)
	}
	if _, err := beta.GetProxy(betaProxy); err != nil {
		t.Fatalf("beta cannot read its own proxy: %v", err)
	}

	bans, err := beta.ListBans(true)
	if err != nil || len(bans) != 1 || bans[0].Reason != "beta" {
		t.Fatalf("beta bans = %+v (%v)", bans, err)
	}
	if n, err := beta.CountBans(true); err != nil || n != 1 {
		t.Fatalf("beta ban count = %d (%v)", n, err)
	}
	if _, err := alpha.BanByCIDR(cidr); err != nil {
		t.Fatalf("alpha lost its own ban: %v", err)
	}
	if _, err := beta.BanByID(1); err == nil {
		t.Fatal("beta resolved a ban by alpha's row id")
	}

	if _, err := alpha.UserByUsername("ops"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("alpha resolved beta's admin: %v", err)
	}
	if n, _ := alpha.CountUsers(); n != 0 {
		t.Fatalf("alpha user count = %d, want 0", n)
	}
	if n, _ := beta.CountUsers(); n != 1 {
		t.Fatalf("beta user count = %d, want 1", n)
	}
	if users, err := alpha.ListUsers(); err != nil || len(users) != 0 {
		t.Fatalf("alpha lists beta's admins: %+v (%v)", users, err)
	}

	if n, err := alpha.CountEvents(); err != nil || n != 1 {
		t.Fatalf("alpha events = %d (%v)", n, err)
	}
	q, total, err := beta.QueryEvents(EventFilter{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour)})
	if err != nil || total != 1 || len(q) != 1 || q[0].Host != "beta.example.com" {
		t.Fatalf("beta events = %+v total %d (%v)", q, total, err)
	}
	events, alphaTotal, err := alpha.QueryEvents(EventFilter{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour)})
	if err != nil || alphaTotal != 1 || len(events) != 1 || events[0].Host != "alpha.example.com" {
		t.Fatalf("alpha events = %+v total %d (%v)", events, alphaTotal, err)
	}

	alphaAudit, err := alpha.ListAudit(10)
	if err != nil || len(alphaAudit) != 1 || alphaAudit[0].User != "admin" {
		t.Fatalf("alpha audit = %+v (%v)", alphaAudit, err)
	}
	betaAudit, err := beta.ListAudit(10)
	if err != nil || len(betaAudit) != 1 || betaAudit[0].User != "ops" {
		t.Fatalf("beta audit = %+v (%v)", betaAudit, err)
	}

	// Writes cannot reach the other site, even with a known row id.
	if err := beta.DeleteProxy(alphaProxy); err == nil {
		t.Fatal("beta deleted alpha's proxy")
	}
	if _, err := alpha.GetProxy(alphaProxy); err != nil {
		t.Fatalf("alpha's proxy is gone: %v", err)
	}
	stolen := &model.Proxy{ID: alphaProxy, Hostname: "hijacked.example.com", Enabled: true, WAFMode: "inherit"}
	if err := beta.UpdateProxy(stolen); err != nil {
		t.Fatal(err)
	}
	if p, err := alpha.GetProxy(alphaProxy); err != nil || p.Hostname != "alpha.example.com" {
		t.Fatalf("beta rewrote alpha's proxy: %+v (%v)", p, err)
	}

	// Settings: a site's own value is private, and host-wide keys are refused.
	if got, err := beta.GetSetting("retention_days"); err != nil || got != "3" {
		t.Fatalf("beta retention = %q (%v)", got, err)
	}
	if got, err := alpha.GetSetting("retention_days"); err != nil || got != "" {
		t.Fatalf("alpha inherited beta's setting: %q (%v)", got, err)
	}
	if err := beta.SetSetting("wan_ip", "203.0.113.9"); !errors.Is(err, ErrHostWideSetting) {
		t.Fatalf("a site moved the host's WAN address: %v", err)
	}
	if err := beta.SetSettings(map[string]string{"retention_days": "5", "wan_ip": "203.0.113.9"}); !errors.Is(err, ErrHostWideSetting) {
		t.Fatalf("a site moved the host's WAN address in bulk: %v", err)
	}
	if err := beta.SetSetting("max_body", "2048"); !errors.Is(err, ErrHostWideSetting) {
		t.Fatalf("a site moved the host's body cap: %v", err)
	}
	if got, _ := alpha.GetSetting("wan_ip"); got == "203.0.113.9" {
		t.Fatal("the host's WAN address changed")
	}
	if got, _ := beta.GetSetting("retention_days"); got != "3" {
		t.Fatalf("a refused bulk write still applied: %q", got)
	}
	if err := alpha.SetSetting("wan_ip", "203.0.113.10"); err != nil {
		t.Fatalf("the default site cannot set a host-wide key: %v", err)
	}
}

// TestRetentionKeepsAnotherSitesEvents is the per-site retention contract: one
// site shortening its history must not delete another site's rows.
func TestRetentionKeepsAnotherSitesEvents(t *testing.T) {
	alpha := openTempStore(t)
	site, err := alpha.CreateSite("bravo", "Bravo", "console.bravo.test")
	if err != nil {
		t.Fatal(err)
	}
	bravo := alpha.InSite(site.ID)
	alphaProxy := testProxy(t, alpha, "alpha.example.com")
	bravoProxy := testProxy(t, bravo, "bravo.example.com")

	old := time.Now().Add(-30 * 24 * time.Hour)
	for _, pair := range []struct {
		st    *Store
		proxy int64
		host  string
	}{{alpha, alphaProxy, "alpha.example.com"}, {bravo, bravoProxy, "bravo.example.com"}} {
		if err := pair.st.InsertEvents([]model.Event{{TS: old, ProxyID: &pair.proxy, Host: pair.host,
			Action: "allow", Stage: "route"}}); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := alpha.DeleteEventsBefore(time.Now().Add(-7 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n, _ := alpha.CountEvents(); n != 0 {
		t.Fatalf("the default site kept %d expired events", n)
	}
	if n, _ := bravo.CountEvents(); n != 1 {
		t.Fatalf("the default site's retention deleted another site's events: %d left", n)
	}
}
