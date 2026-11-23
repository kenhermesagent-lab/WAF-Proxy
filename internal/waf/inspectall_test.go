package waf

import (
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// A simulation needs every rule that fired, not only the one the log names.
func TestInspectAllKeepsEveryMatchedRule(t *testing.T) {
	e, err := compile(model.Profile{ID: 1, Name: "test", Mode: "block", Paranoia: 1, Anomaly: 5, MaxBody: 131072}, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E&id=1%27+OR+%271%27%3D%271", nil)
	ip := netip.MustParseAddr("203.0.113.7")

	res, matches := e.InspectAll(req, nil, ip)
	if !res.Blocked {
		t.Fatalf("SQL injection was not blocked: %+v", res)
	}
	if len(matches) < 2 {
		t.Fatalf("matches = %+v, want several rules", matches)
	}
	seen := map[int]bool{}
	for _, m := range matches {
		if m.RuleID == 0 {
			t.Errorf("match has no rule id: %+v", m)
		}
		seen[m.RuleID] = true
	}
	if !seen[res.RuleID] {
		t.Errorf("the reported rule %d is missing from %v", res.RuleID, seen)
	}

	// Inspect keeps the behaviour it had before the traversal was shared.
	one := e.Inspect(req, nil, ip)
	if one.Blocked != res.Blocked || one.RuleID != res.RuleID || one.Label != res.Label || one.Matched != res.Matched {
		t.Fatalf("Inspect = %+v, InspectAll verdict = %+v", one, res)
	}
}
