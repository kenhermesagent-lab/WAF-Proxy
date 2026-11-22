package policy

import (
	"strconv"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// A global whitelist is checked above the global blocklist and above explicit
// block policies, and a global blocklist applies to every host even when the
// host selects no access profile.
func TestGlobalListsApplyToEveryProxy(t *testing.T) {
	pol, st, _ := newEngine(t)
	allow := &model.AccessList{Kind: model.ListKindAllow, Name: "office", IPs: "203.0.113.7", Countries: "DE"}
	block := &model.AccessList{Kind: model.ListKindBlock, Name: "scanners", IPs: "198.51.100.0/24", Countries: "RU"}
	if err := st.CreateAccessList(allow); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAccessList(block); err != nil {
		t.Fatal(err)
	}
	// The same address is explicitly blocked by a policy row: the global
	// whitelist still wins, which is what "allow on top" means in the console.
	if _, err := st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyIPBlacklist, Value: "203.0.113.7", Action: "block", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSettings(map[string]string{
		"global_whitelist_ids": strconv.FormatInt(allow.ID, 10),
		"global_blocklist_ids": strconv.FormatInt(block.ID, 10),
	}); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}

	if v := screenGeo(pol, nil, "198.51.100.9", "US"); v.Action != "block" || v.Stage != "global-list" || v.List != "scanners" {
		t.Fatalf("global blocklist did not block: %+v", v)
	}
	if v := screenGeo(pol, nil, "203.0.113.7", "US"); v.Action != "allow" || v.Stage != "global-list" || v.List != "office" {
		t.Fatalf("global whitelist did not win over the blocklist: %+v", v)
	}
	if v := screenGeo(pol, nil, "198.51.100.20", "RU"); v.Action != "block" || v.List != "scanners" {
		t.Fatalf("global blocklist country did not block: %+v", v)
	}
	if v := screenGeo(pol, nil, "192.0.2.5", "US"); v.Action != "allow" || v.Stage != "route" {
		t.Fatalf("an unlisted address was not left alone: %+v", v)
	}

	// Detaching both lists restores the ordinary pipeline.
	if err := st.SetSettings(map[string]string{"global_whitelist_ids": "", "global_blocklist_ids": ""}); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}
	if v := screenGeo(pol, nil, "198.51.100.9", "US"); v.Action != "allow" {
		t.Fatalf("a detached global blocklist kept blocking: %+v", v)
	}
	if v := screenGeo(pol, nil, "203.0.113.7", "US"); v.Action != "block" || v.Stage != "ip-blacklist" {
		t.Fatalf("detaching the whitelist did not restore the block policy: %+v", v)
	}
}
