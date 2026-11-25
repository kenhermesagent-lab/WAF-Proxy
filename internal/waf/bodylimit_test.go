package waf

import (
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// A body above the profile's inspection limit is a limit refusal, not a
// protocol violation: the label the console shows has to say which.
func TestBodyLimitNamesItself(t *testing.T) {
	e, err := compile(model.Profile{ID: 1, Name: "test", Mode: "block", Paranoia: 1, Anomaly: 5, MaxBody: 1024}, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/upload", strings.NewReader(""))
	body := []byte(strings.Repeat("A", 4096))
	res, _ := e.InspectAllWith(req, body, netip.MustParseAddr("192.0.2.10"), InspectOptions{})
	if !res.Blocked || res.RuleID != 200004 {
		t.Fatalf("blocked = %v, rule = %d, want 200004", res.Blocked, res.RuleID)
	}
	if res.Label != "waf-body-limit" {
		t.Fatalf("label = %q, want waf-body-limit", res.Label)
	}
	if !strings.Contains(res.Message, "1024") {
		t.Fatalf("message = %q, want the limit named", res.Message)
	}
	if got := Label(200004); got != "waf-body-limit" {
		t.Fatalf("Label(200004) = %q", got)
	}
}
