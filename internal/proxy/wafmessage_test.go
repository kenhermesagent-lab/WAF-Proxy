package proxy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// The event has to carry the rule's own message, which names what it objected
// to. Overwriting it with the label left "protocol-violation" and no way to
// tell a restricted header from a framing problem.
func TestWAFBlockRecordsTheRuleMessage(t *testing.T) {
	h := newHarness(t)
	profiles, err := h.st.ListProfiles()
	if err != nil || len(profiles) == 0 {
		t.Fatalf("profiles: %v", err)
	}
	h.proxy.ProfileID = &profiles[0].ID
	h.proxy.WAFMode = "block"
	attachBodySkip(t, h, 256<<20, []model.BodySkip{{Method: "POST", Prefix: "/seafhttp/"}})

	rec := h.request(http.MethodPost, testHost, "/seafhttp/upload-aj/ea612696", strings.Repeat("x", 2<<10),
		map[string]string{
			"Content-Type": "multipart/form-data; boundary=abc",
			"Expect":       "100-continue",
		})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 from the restricted-header rule", rec.Code)
	}
	ev := h.waitEvent(t, func(e model.Event) bool { return strings.HasPrefix(e.Path, "/seafhttp/upload-aj/") })
	if ev.RuleID != "920450" {
		t.Fatalf("rule = %q, want 920450", ev.RuleID)
	}
	if !strings.Contains(ev.RuleMsg, "/expect/") {
		t.Fatalf("rule_msg = %q, want the restricted header named", ev.RuleMsg)
	}
}
