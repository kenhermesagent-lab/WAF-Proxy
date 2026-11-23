package policy

import (
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

func bundlePack() []waf.Bundle {
	return []waf.Bundle{{Name: "cve-2026-11", Version: "2", Rules: []waf.BundleRule{{
		ID: 990417, Message: "template injection probe", Severity: "CRITICAL",
		Target: "REQUEST_URI", Operator: "@contains /wp-login.php",
	}}}}
}

// inspectWithBundle builds a profile with one bundle mode, attaches the pack
// and runs the WAF stage through the real engine.
func inspectWithBundle(t *testing.T, mode, siteMode string) (model.Verdict, WAFInfo) {
	t.Helper()
	pol, st, _ := newEngine(t)
	profile := model.Profile{
		Name: "bundle " + mode, Mode: "block", Paranoia: 1, Anomaly: 5,
		AllowedMethods: "GET,HEAD", MaxBody: 131072,
		BundleModes: map[string]string{"cve-2026-11": mode},
	}
	if err := st.CreateProfile(&profile); err != nil {
		t.Fatal(err)
	}
	pol.wafs = waf.NewSet(nil, pol.log)
	pol.SetBundleRules(bundlePack)
	if err := pol.ReloadWAF(); err != nil {
		t.Fatal(err)
	}
	proxy := &model.Proxy{ID: 1, Hostname: "app.example", Enabled: true, ProfileID: &profile.ID, WAFMode: siteMode}
	req := httptest.NewRequest("GET", "https://app.example/wp-login.php", nil)
	return pol.Inspect(&Request{
		Proxy: proxy, Host: "app.example", Method: "GET", Path: "/wp-login.php",
		Addr: netip.MustParseAddr("203.0.113.9"), HTTP: req,
	})
}

func TestBundleModeIsPerProfile(t *testing.T) {
	verdict, info := inspectWithBundle(t, model.BundleBlock, "inherit")
	if verdict.Action != "block" || verdict.Status != 403 {
		t.Fatalf("block mode = %+v, want a 403", verdict)
	}
	if verdict.Rule != "990417" {
		t.Fatalf("block reported rule %q", verdict.Rule)
	}
	if info.RuleID != 990417 || info.Label != "bundle" {
		t.Fatalf("info = %+v", info)
	}

	verdict, _ = inspectWithBundle(t, model.BundleLog, "inherit")
	if verdict.Action != "log" || verdict.Status != 200 || verdict.Rule != "990417" {
		t.Fatalf("log mode = %+v, want a logged rule", verdict)
	}

	verdict, _ = inspectWithBundle(t, model.BundleOff, "inherit")
	if verdict.Action != "allow" || verdict.Stage != "waf" {
		t.Fatalf("off mode = %+v, want an allow with no match", verdict)
	}
}

// A site pinned to detect-only keeps that promise even when its profile says
// the bundle may block: the per-site override is the narrower setting.
func TestSiteDetectOverrideDowngradesBundleBlock(t *testing.T) {
	verdict, _ := inspectWithBundle(t, model.BundleBlock, "detect")
	if verdict.Action != "log" || verdict.Status != 200 {
		t.Fatalf("detect site = %+v, want a log", verdict)
	}
}
