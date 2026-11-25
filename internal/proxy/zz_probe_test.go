package proxy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func TestProbeBlockedUploadRecord(t *testing.T) {
	h := newHarness(t)
	profiles, err := h.st.ListProfiles()
	if err != nil || len(profiles) == 0 {
		t.Fatalf("profiles: %v", err)
	}
	h.proxy.ProfileID = &profiles[0].ID
	h.proxy.WAFMode = "block"
	attachBodySkip(t, h, 256<<20, []model.BodySkip{{Method: "POST", Prefix: "/seafhttp/"}})

	rec := h.request(http.MethodPost, testHost, "/seafhttp/upload-aj/ea612696?ret-json=1",
		strings.Repeat("x", 2<<20), map[string]string{
			"Content-Type": "multipart/form-data; boundary=abc",
			"Expect":       "100-continue",
		})
	ev := h.waitEvent(t, func(e model.Event) bool { return strings.HasPrefix(e.Path, "/seafhttp/upload-aj/") })
	t.Logf("status=%d stage=%q rule=%q msg=%q", rec.Code, ev.Stage, ev.RuleID, ev.RuleMsg)
}
