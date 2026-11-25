package store

import (
	"errors"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func TestSettingsAndPolicies(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	kv, err := st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if kv["base_domain"] != "example.com" {
		t.Fatalf("setting round trip failed: %q", kv["base_domain"])
	}

	p := &model.Policy{Scope: "global", Kind: model.PolicyCountryBlacklist, Value: "RU,CN", Action: "block", Enabled: true}
	id, err := st.CreatePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	list, err := st.ListPolicies()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Value != "RU,CN" {
		t.Fatalf("unexpected policies: %+v", list)
	}
	if err := st.DeletePolicy(id); err != nil {
		t.Fatal(err)
	}
	if list, _ = st.ListPolicies(); len(list) != 0 {
		t.Fatalf("policy not deleted: %+v", list)
	}
}

func TestBanExpiry(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	past := time.Now().Add(-time.Hour)
	if _, err := st.AddBan(&model.Ban{CIDR: "203.0.113.0/24", Reason: "test", Source: "manual", CreatedAt: past.Add(-time.Hour), ExpiresAt: &past}); err != nil {
		t.Fatal(err)
	}
	if err := st.PurgeBans(); err != nil {
		t.Fatal(err)
	}
	live, err := st.ListBans(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 0 {
		t.Fatalf("expired ban still listed: %+v", live)
	}
}

func TestDeleteGateUserRevokesSessionsAndACL(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	proxyID, err := st.CreateProxy(&model.Proxy{Hostname: "media.example.com", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	uid, err := st.CreateGateUser("alice", "hash", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetGateACL(proxyID, []string{"alice"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateGateSession("sess-1", proxyID, "alice", "203.0.113.5", "ua", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.LookupGateSession("sess-1", proxyID); !ok {
		t.Fatal("session missing before delete")
	}

	if err := st.DeleteGateUser(uid); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.LookupGateSession("sess-1", proxyID); ok {
		t.Fatal("deleted gate account kept a live visitor session")
	}
	if acl, err := st.GateACL(proxyID); err != nil || len(acl) != 0 {
		t.Fatalf("deleted account still on the ACL: %v (%v)", acl, err)
	}
	if err := st.DeleteGateUser(uid); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete = %v, want ErrNotFound", err)
	}
}

func TestUsernameBanInvalidatesLiveGateSession(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	proxyID, err := st.CreateProxy(&model.Proxy{Hostname: "media.example.com", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGateUser("alice", "hash", "", false); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateGateSession("cookie-secret", proxyID, "alice", "203.0.113.5", "ua", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.LookupGateSession("cookie-secret", proxyID); !ok {
		t.Fatal("session missing before the username block")
	}
	if err := st.AddUsernameBan("alice", "compromised", "admin", nil); err != nil {
		t.Fatal(err)
	}
	if banned, err := st.UsernameBanned("alice"); err != nil || !banned {
		t.Fatalf("UsernameBanned = (%v, %v)", banned, err)
	}
	// Even if the revocation delete is lost, the session lookup must refuse a
	// blocked username.
	if _, ok := st.LookupGateSession("cookie-secret", proxyID); ok {
		t.Fatal("blocked username still passed the session lookup")
	}
	sessions, err := st.GateSessions(10)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("GateSessions = (%+v, %v)", sessions, err)
	}
	if sessions[0].Ref == "cookie-secret" {
		t.Fatalf("session ref exposed the cookie: %+v", sessions[0])
	}
	if _, err := st.DeleteGateSessionByRef(sessions[0].Ref); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.CountGateSessions(); n != 0 {
		t.Fatalf("session count after revoke = %d", n)
	}
}

func TestCertRenewModeDefaultsAndUpdates(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	id, err := st.SaveCert(&model.Cert{Domains: "example.com", Provider: "duckdns", Status: "pending"})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := st.GetCert(id)
	if err != nil {
		t.Fatal(err)
	}
	if cert.RenewMode != model.CertRenewBeforeExpiry {
		t.Fatalf("default renew_mode = %q, want %q", cert.RenewMode, model.CertRenewBeforeExpiry)
	}
	if err := st.SetCertRenewMode(id, model.CertRenewEvery2Months); err != nil {
		t.Fatal(err)
	}
	cert, err = st.GetCert(id)
	if err != nil {
		t.Fatal(err)
	}
	if cert.RenewMode != model.CertRenewEvery2Months {
		t.Fatalf("updated renew_mode = %q, want %q", cert.RenewMode, model.CertRenewEvery2Months)
	}
	if err := st.SetCertRenewMode(id+1, model.CertRenewMonthly); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing certificate update = %v, want ErrNotFound", err)
	}
}

func TestDeleteFeedReportsRowsAffected(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	id, err := st.CreateFeed(&model.Feed{Name: "custom", URL: "https://example.com/list.txt"})
	if err != nil {
		t.Fatal(err)
	}
	removed, err := st.DeleteFeed(id)
	if err != nil || !removed {
		t.Fatalf("custom feed delete = (%v, %v), want (true, nil)", removed, err)
	}
	if removed, err = st.DeleteFeed(id); err != nil || removed {
		t.Fatalf("second delete = (%v, %v), want (false, nil)", removed, err)
	}
	feeds, err := st.ListFeeds()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range feeds {
		if !f.Builtin {
			continue
		}
		if removed, err := st.DeleteFeed(f.ID); err != nil || removed {
			t.Fatalf("built-in feed delete = (%v, %v), want (false, nil)", removed, err)
		}
		return
	}
	t.Fatal("no built-in feed seeded")
}

func TestSeedFeedsRetiresDeadBuiltins(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// A custom feed that reuses a retired name must survive the cleanup.
	if _, err := st.CreateFeed(&model.Feed{Name: "URLhaus hosts", URL: "https://example.com/custom.txt"}); err != nil {
		t.Fatal(err)
	}
	// Simulate a database seeded by an older release.
	if _, err := st.db.Exec(`INSERT INTO feeds(name, url, action, interval_s, enabled, builtin, state)
		VALUES('Spamhaus EDROP', 'https://www.spamhaus.org/drop/edrop.txt', 'block', 3600, 0, 1, 'pending')`); err != nil {
		t.Fatal(err)
	}
	if err := st.seedFeeds(); err != nil {
		t.Fatal(err)
	}
	feeds, err := st.ListFeeds()
	if err != nil {
		t.Fatal(err)
	}
	custom := 0
	for _, f := range feeds {
		if f.Builtin && (f.Name == "Spamhaus EDROP" || f.Name == "URLhaus hosts") {
			t.Errorf("retired built-in %q is still seeded", f.Name)
		}
		if !f.Builtin && f.Name == "URLhaus hosts" {
			custom++
		}
	}
	if custom != 1 {
		t.Errorf("custom URLhaus feed = %d, want 1 left alone", custom)
	}

	// The added keyless lists seed exactly once and stay disabled, so an
	// upgrade never starts blocking new ranges on its own.
	if err := st.seedFeeds(); err != nil {
		t.Fatal(err)
	}
	feeds, err = st.ListFeeds()
	if err != nil {
		t.Fatal(err)
	}
	added := map[string]bool{
		"Blocklist.de attackers": true, "GreenSnow blocklist": true, "Binary Defense banlist": true,
		"CINS Army": true, "BruteForceBlocker": true, "IPSum level 3": true,
		"Spamhaus DROP IPv6": true, "ET firewall block list": true,
	}
	seen := map[string]int{}
	for _, f := range feeds {
		if !added[f.Name] {
			continue
		}
		seen[f.Name]++
		if !f.Builtin {
			t.Errorf("%s is not marked built-in", f.Name)
		}
		if f.Enabled {
			t.Errorf("%s is enabled by default", f.Name)
		}
	}
	for name := range added {
		if seen[name] != 1 {
			t.Errorf("built-in feed %q seeded %d times, want 1", name, seen[name])
		}
	}
}

// A feed created from a site's console must be visible to the unscoped handle
// the intel engine uses, or its refresh records nothing and the console reads a
// feed that never loads. Another site must still not see it.
func TestFeedsAreVisibleToTheUnscopedEngine(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	site := st.InSite(7)
	id, err := site.CreateFeed(&model.Feed{Name: "site feed", Local: true, Enabled: true,
		Filename: "list.txt", LocalPath: "/tmp/list.txt"})
	if err != nil {
		t.Fatal(err)
	}
	engine := st.Unscoped()
	feeds, err := engine.ListFeeds()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range feeds {
		if f.ID == id {
			found = true
		}
	}
	if !found {
		t.Fatalf("the engine's ListFeeds does not include the site's feed %d", id)
	}
	loaded, err := engine.FeedByID(id)
	if err != nil || loaded.LocalPath != "/tmp/list.txt" {
		t.Fatalf("engine FeedByID = (%+v, %v), want the local path", loaded, err)
	}
	if err := engine.UpdateFeedFetch(id, "", "", 3, "ok", ""); err != nil {
		t.Fatal(err)
	}
	if got, err := site.FeedByID(id); err != nil || got.State != "ok" || got.LastCount != 3 {
		t.Fatalf("after the engine recorded the load: %+v %v", got, err)
	}
	other, err := st.InSite(8).ListFeeds()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range other {
		if f.ID == id {
			t.Fatal("another site sees this site's feed")
		}
	}
	removed, err := engine.DeleteFeed(id)
	if err != nil || !removed {
		t.Fatalf("engine delete = (%v, %v), want (true, nil)", removed, err)
	}
}
