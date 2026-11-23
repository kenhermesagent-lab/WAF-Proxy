package waf

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func bundleSet(t *testing.T, mode string) (*Set, int64) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewSet(nil, log)
	s.SetBundles([]Bundle{{Name: "cve-2026-11", Version: "2", Rules: []BundleRule{{
		ID: 990417, Message: "template injection probe", Severity: "CRITICAL",
		Target: "REQUEST_URI", Operator: "@contains wp-login",
	}}}})
	profile := model.Profile{ID: 1, Name: "web", Mode: "block", Paranoia: 1, Anomaly: 5, MaxBody: 131072}
	if mode != "" {
		profile.BundleModes = map[string]string{"cve-2026-11": mode}
	}
	s.Reload([]model.Profile{profile})
	id := int64(1)
	return s, id
}

func TestBundleRuleReportsItsPack(t *testing.T) {
	s, id := bundleSet(t, "")
	req := httptest.NewRequest("GET", "https://app.example/wp-login.php", nil)
	res, matches := s.For(&id).InspectAll(req, nil, netip.MustParseAddr("203.0.113.9"))

	if !res.Matched {
		t.Fatal("the bundle rule did not match")
	}
	if res.Blocked {
		t.Fatal("a bundle rule must not interrupt; the policy layer decides the action")
	}
	var found bool
	for _, m := range matches {
		if m.RuleID == 990417 && m.Origin == "bundle" && m.Bundle == "cve-2026-11" && m.BundleVersion == "2" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the match lost its origin: %+v", matches)
	}
}

func TestOffBundleAddsNoRules(t *testing.T) {
	s, id := bundleSet(t, model.BundleOff)
	req := httptest.NewRequest("GET", "https://app.example/wp-login.php", nil)
	res, _ := s.For(&id).InspectAll(req, nil, netip.MustParseAddr("203.0.113.9"))
	if res.Matched {
		t.Fatal("a bundle set to off still produced a match")
	}
}

func TestBundleValidation(t *testing.T) {
	ok := Bundle{Name: "pack", Version: "1", Rules: []BundleRule{{
		ID: 990001, Message: "probe", Severity: "critical", Target: "ARGS", Operator: "@contains x",
	}}}
	if err := ValidateBundle(ok); err != nil {
		t.Fatalf("a valid bundle was refused: %v", err)
	}
	cases := map[string]Bundle{
		"id outside the bundle range": {Name: "p", Version: "1", Rules: []BundleRule{{
			ID: 942100, Message: "m", Severity: "CRITICAL", Target: "ARGS", Operator: "@contains x"}}},
		"target escapes the directive": {Name: "p", Version: "1", Rules: []BundleRule{{
			ID: 990001, Message: "m", Severity: "CRITICAL", Target: `ARGS" `, Operator: "@contains x"}}},
		"operator is not an operator": {Name: "p", Version: "1", Rules: []BundleRule{{
			ID: 990001, Message: "m", Severity: "CRITICAL", Target: "ARGS", Operator: "contains x"}}},
		"newline in operator": {Name: "p", Version: "1", Rules: []BundleRule{{
			ID: 990001, Message: "m", Severity: "CRITICAL", Target: "ARGS", Operator: "@contains x\nSecRuleEngine Off"}}},
		"unknown severity": {Name: "p", Version: "1", Rules: []BundleRule{{
			ID: 990001, Message: "m", Severity: "very bad", Target: "ARGS", Operator: "@contains x"}}},
		"duplicate id": {Name: "p", Version: "1", Rules: []BundleRule{
			{ID: 990001, Message: "a", Severity: "CRITICAL", Target: "ARGS", Operator: "@contains x"},
			{ID: 990001, Message: "b", Severity: "CRITICAL", Target: "ARGS", Operator: "@contains y"},
		}},
	}
	for name, b := range cases {
		if err := ValidateBundle(b); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := ValidateCompile("pack", ok.Rules); err != nil {
		t.Fatalf("a valid bundle did not compile: %v", err)
	}
}
