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
