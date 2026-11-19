package store

import (
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
