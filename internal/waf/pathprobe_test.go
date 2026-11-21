package waf

import (
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// A scanner can put the target file in the path instead of a parameter. The
// CRS LFI rules inspect arguments, so "/etc/passwd" reached the backend while
// "?file=/etc/passwd" was blocked. The path probe rule closes that gap.
func TestPathStyleFileProbeIsBlocked(t *testing.T) {
	id := int64(1)
	set := NewSet([]model.Profile{{
		ID: id, Name: "probe", Mode: "block", Paranoia: 1, Anomaly: 5, MaxBody: 131072,
	}}, slog.Default())
	engine := set.For(&id)
	if engine == nil {
		t.Fatal("no engine compiled")
	}

	probes := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/root/.ssh/id_rsa",
		"/proc/self/environ",
		"/proc/1/cmdline",
		"/etc/sudoers",
	}
	for _, path := range probes {
		req := httptest.NewRequest("GET", "https://app.example.com"+path, nil)
		if res := engine.Inspect(req, nil, netip.MustParseAddr("203.0.113.9")); !res.Blocked {
			t.Errorf("%s was not blocked (matched=%v rule=%d)", path, res.Matched, res.RuleID)
		}
	}

	// The CRS local-file-inclusion rules leave a bare /etc/passwd in the path
	// alone; that is the case this rule exists for, so pin the reporting too.
	for _, path := range []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers"} {
		req := httptest.NewRequest("GET", "https://app.example.com"+path, nil)
		res := engine.Inspect(req, nil, netip.MustParseAddr("203.0.113.9"))
		if res.RuleID != 900110 {
			t.Errorf("%s was blocked by rule %d, want the path probe rule", path, res.RuleID)
		}
	}

	// Ordinary application paths that merely mention these names must pass.
	allowed := []string{"/etc/passwd-docs", "/api/v1/etc"}
	for _, path := range allowed {
		req := httptest.NewRequest("GET", "https://app.example.com"+path, nil)
		if res := engine.Inspect(req, nil, netip.MustParseAddr("203.0.113.9")); res.Blocked {
			t.Errorf("%s was blocked by rule %d", path, res.RuleID)
		}
	}
}
