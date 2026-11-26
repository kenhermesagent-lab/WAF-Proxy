package policy

import (
	"net/netip"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// A path closed from a security finding is refused on its host even for an
// allowlisted address and even for the scanner's own trusted probe. The scan
// has to observe the same refusal a stranger gets, or its rerun cannot prove
// the exposure closed.
func TestDenyPathBlocksEveryCaller(t *testing.T) {
	pol, st, _ := newEngine(t)
	if _, err := st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyIPWhitelist, Value: "203.0.113.7", Action: "allow", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	pol.ScanTrust = func(token string) bool { return token == "run-token" }
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}

	proxy := &model.Proxy{ID: 1, Hostname: "app.example.com", Enabled: true, DenyPaths: []string{"/actuator"}}
	req := &Request{
		Proxy: proxy, Addr: netip.MustParseAddr("203.0.113.7"),
		Method: "GET", Path: "/actuator/env", ScanToken: "run-token",
	}
	v := pol.Screen(req)
	if v.Action != "block" || v.Stage != "path-block" || v.Status != 403 {
		t.Fatalf("a closed path = %+v, want a 403 path-block", v)
	}

	// The entry covers itself and its subtree, not a longer sibling.
	req.Path = "/actuatorx"
	if v := pol.Screen(req); v.Stage == "path-block" {
		t.Fatalf("a longer sibling matched the deny entry: %+v", v)
	}
}
