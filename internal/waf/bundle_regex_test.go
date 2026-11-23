package waf

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// A pack's operator is a regex as often as not, so the escaping that keeps a
// directive intact must not eat the backslash classes inside it.
func TestBundleOperatorKeepsRegexEscapes(t *testing.T) {
	s := NewSet(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetBundles([]Bundle{{Name: "sqli", Version: "1", Rules: []BundleRule{{
		ID: 990002, Message: "union select in a parameter", Severity: "CRITICAL",
		Target: "ARGS", Operator: `@rx (?i)\bunion\b\s+select\b`,
	}}}})
	s.Reload([]model.Profile{{ID: 1, Name: "web", Mode: "block", Paranoia: 1, Anomaly: 5, MaxBody: 131072}})
	id := int64(1)

	hit := httptest.NewRequest("GET", "https://app.example/?q=1%20union%20select%20x", nil)
	if res, _ := s.For(&id).InspectAll(hit, nil, netip.MustParseAddr("203.0.113.9")); !res.Matched {
		t.Fatal("the regex operator stopped matching: its escapes were rewritten")
	}
	miss := httptest.NewRequest("GET", "https://app.example/?q=union+all", nil)
	if res, _ := s.For(&id).InspectAll(miss, nil, netip.MustParseAddr("203.0.113.9")); res.Matched {
		t.Fatal("the regex matched a request it should not")
	}
}
