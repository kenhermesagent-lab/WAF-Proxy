package store

import (
	"os"
	"path/filepath"
	"testing"

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
