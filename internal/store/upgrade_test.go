package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// The fixture is a database written by 1.21. Keeping one in the tree is the
// only way a later migration gets tested against real rows instead of a schema
// that was created by the code under test.
const upgradeFixture = "testdata/db-v1.21.sqlite"

func TestUpgradeFromPreviousReleaseDatabase(t *testing.T) {
	data, err := os.ReadFile(upgradeFixture)
	if err != nil {
		t.Fatalf("read fixture: %v (regenerate with WAFPROXY_WRITE_FIXTURE=1 go test -run TestWriteUpgradeFixture ./internal/store)", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wafproxy.db"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open the previous release's database: %v", err)
	}
	defer st.Close()

	if n, err := st.CountUsers(); err != nil || n != 1 {
		t.Fatalf("users = %d (%v), want 1", n, err)
	}
	proxies, err := st.ListProxies()
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 1 || proxies[0].Hostname != "app.example.com" || !proxies[0].Enabled || proxies[0].BotLevel != "light" {
		t.Fatalf("proxies = %+v", proxies)
	}
	policies, err := st.ListPolicies()
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 || policies[0].Value != "203.0.113.0/24" {
		t.Fatalf("policies = %+v", policies)
	}
	lists, err := st.ListAccessLists()
	if err != nil {
		t.Fatal(err)
	}
	if len(lists) != 1 || lists[0].Name != "office" || lists[0].IPs != "198.51.100.0/24" {
		t.Fatalf("lists = %+v", lists)
	}
	if base, err := st.GetSetting("base_domain"); err != nil || base != "upgrade.example.com" {
		t.Fatalf("base_domain = %q (%v)", base, err)
	}
}

// The rollback fixture is a 1.55.1 database after that update was rolled back.
// The binary that ran meanwhile wrote rows that name no site, one of each
// repeating a row the default site already owns: a permanent ban for an address
// the site bans temporarily, and a newer definition of a saved view. The schema
// has not changed since 1.55.1, so the fixture still covers the keys that
// release left behind.
const rollbackFixture = "testdata/db-v1.55.1-rollback.sqlite"

func TestUpgradeFromRolledBackDatabase(t *testing.T) {
	data, err := os.ReadFile(rollbackFixture)
	if err != nil {
		t.Fatalf("read fixture: %v (regenerate with WAFPROXY_WRITE_ROLLBACK_FIXTURE=1 go test -run TestWriteRollbackFixture ./internal/store)", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wafproxy.db"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open the rolled-back database: %v", err)
	}
	defer st.Close()

	// The duplicate address is adopted once, and the stronger ban survived.
	ban, err := st.BanByCIDR("198.51.100.7")
	if err != nil {
		t.Fatalf("adopted ban: %v", err)
	}
	if !ban.Permanent || ban.Source != "crowdsec" {
		t.Fatalf("adopted ban = %+v, want the permanent crowdsec row", ban)
	}
	var bans int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM bans WHERE cidr = '198.51.100.7' AND site_id = ?`, st.SiteID()).
		Scan(&bans); err != nil || bans != 1 {
		t.Fatalf("bans for the adopted address = %d (%v), want 1", bans, err)
	}

	// The unowned view's newer definition replaced the older one of its name.
	views, err := st.ListLogViews()
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].Name != "errors" || views[0].Query != "status >= 400" || views[0].UpdatedBy != "ops" {
		t.Fatalf("views = %+v, want only the newer errors view", views)
	}

	// The rolled-back binary's trusted device and reset still resolve here.
	if _, ok := st.TrustedDeviceUser("rollback-trusted"); !ok {
		t.Fatal("the adopted trusted device does not resolve on the default site")
	}
	var resets int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM password_resets WHERE token_hash = 'rollback-reset' AND site_id = ?`, st.SiteID()).
		Scan(&resets); err != nil || resets != 1 {
		t.Fatalf("adopted password reset = %d (%v), want 1", resets, err)
	}

	// Another site's ban for the same address is left alone.
	two, err := st.SiteBySlug("two")
	if err != nil {
		t.Fatal(err)
	}
	if other, err := st.InSite(two.ID).BanByCIDR("198.51.100.7"); err != nil || other.Reason != "two" {
		t.Fatalf("second site's ban = %+v (%v)", other, err)
	}

	// Nothing the rolled-back binary wrote is left unowned.
	for _, table := range []string{"bans", "log_views", "trusted_devices", "password_resets"} {
		var unowned int
		if err := st.db.QueryRow(`SELECT COUNT(*) FROM ` + table + ` WHERE site_id = 0`).Scan(&unowned); err != nil {
			t.Fatal(err)
		}
		if unowned != 0 {
			t.Fatalf("%s has %d rows without a site after the upgrade", table, unowned)
		}
	}
}

// TestWriteRollbackFixture regenerates the rollback fixture. It is skipped by
// default: the file must stay at the shape the rolled-back release left behind.
func TestWriteRollbackFixture(t *testing.T) {
	if os.Getenv("WAFPROXY_WRITE_ROLLBACK_FIXTURE") != "1" {
		t.Skip("set WAFPROXY_WRITE_ROLLBACK_FIXTURE=1 to regenerate the fixture")
	}
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	userID, err := st.CreateUser("admin", "hash-of-a-password", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.CreateSite("two", "Two", "two.example.test")
	if err != nil {
		t.Fatal(err)
	}
	soon := time.Now().Add(time.Hour)
	if _, err := st.AddBan(&model.Ban{CIDR: "198.51.100.7", Reason: "manual ban", Source: "manual", ExpiresAt: &soon}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InSite(second.ID).AddBan(&model.Ban{CIDR: "198.51.100.7", Reason: "two", Source: "manual"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveLogView("errors", "status = 500", "admin"); err != nil {
		t.Fatal(err)
	}
	// The rows the rolled-back binary writes without a site. The trusted device
	// and reset live to 2100 so the fixture does not expire.
	forever := stamp(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC))
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO bans(cidr, reason, source, permanent, hits, created_by, created_at, site_id)
			VALUES('198.51.100.7', 'crowdsec: ssh:bruteforce', 'crowdsec', 1, 0, 'crowdsec', ?, 0)`,
			[]any{stamp(time.Now().Add(time.Minute))}},
		{`INSERT INTO log_views(name, query, updated_by, updated_at, site_id)
			VALUES('errors', 'status >= 400', 'ops', ?, 0)`,
			[]any{stamp(time.Now().Add(time.Minute))}},
		{`INSERT INTO trusted_devices(token_hash, user_id, site_id, created_at, expires_at)
			VALUES('rollback-trusted', ?, 0, ?, ?)`,
			[]any{userID, stamp(time.Now()), forever}},
		{`INSERT INTO password_resets(token_hash, user_id, site_id, created_at, expires_at)
			VALUES('rollback-reset', ?, 0, ?, ?)`,
			[]any{userID, stamp(time.Now()), forever}},
	} {
		if _, err := st.db.Exec(stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	// Merge the write-ahead log and drop free pages before copying it, so the
	// committed fixture stays small.
	if _, err := st.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("VACUUM"); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "wafproxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rollbackFixture, data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s (%d bytes)", rollbackFixture, len(data))
}

// TestWriteUpgradeFixture regenerates the fixture. It is skipped by default
// because the file must stay frozen at the release it was taken from: a
// fixture written by today's code proves nothing about yesterday's.
func TestWriteUpgradeFixture(t *testing.T) {
	if os.Getenv("WAFPROXY_WRITE_FIXTURE") != "1" {
		t.Skip("set WAFPROXY_WRITE_FIXTURE=1 to regenerate the fixture")
	}
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser("admin", "hash-of-a-password", "", "", false); err != nil {
		t.Fatal(err)
	}
	profile := &model.Profile{Name: "Upgrade", Mode: "block", Paranoia: 2, Anomaly: 5, MaxBody: 65536}
	if err := st.CreateProfile(profile); err != nil {
		t.Fatal(err)
	}
	proxy := &model.Proxy{Hostname: "app.example.com", Enabled: true, ProfileID: &profile.ID,
		WAFMode: "inherit", BotLevel: "light", Fingerprint: "strict"}
	if _, err := st.CreateProxy(proxy); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreatePolicy(&model.Policy{Scope: "global", Kind: model.PolicyIPWhitelist,
		Value: "203.0.113.0/24", Action: "allow", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAccessList(&model.AccessList{Kind: model.ListKindAllow, Name: "office",
		IPs: "198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("base_domain", "upgrade.example.com"); err != nil {
		t.Fatal(err)
	}
	// Merge the write-ahead log into the database file and drop free pages
	// before copying it, so the committed fixture stays small.
	if _, err := st.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("VACUUM"); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "wafproxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(upgradeFixture, data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s (%d bytes)", upgradeFixture, len(data))
}
