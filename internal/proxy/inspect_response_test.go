package proxy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

const leakyBody = "You have an error in your SQL syntax"

// A blocked response must never reach the client, not even its status line.
func TestResponseInspectionBlocksBeforeHeaders(t *testing.T) {
	h := newHarness(t)
	attachProfile(t, h, model.Profile{Name: "resp-block", Responses: "block"})

	rec := h.request(http.MethodGet, testHost, "/leak", "", nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for a blocked response", rec.Code)
	}
	if strings.Contains(rec.Body.String(), leakyBody) {
		t.Fatalf("the upstream body reached the client: %q", rec.Body.String())
	}
	e := h.waitEvent(t, func(e model.Event) bool { return e.Stage == "response-waf" })
	if e.RuleID != "951230" || e.Action != "block" || e.Status != http.StatusBadGateway {
		t.Fatalf("event = %+v, want a blocked 951230", e)
	}
}

// Saving the profile in the console must take effect without restarting the
// proxy, so the setting is read from the policy engine, not the cached edge.
func TestResponseInspectionFollowsASavedProfile(t *testing.T) {
	h := newHarness(t)
	attachProfile(t, h, model.Profile{Name: "resp-live"})

	if rec := h.request(http.MethodGet, testHost, "/leak", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("status with responses off = %d, want 200", rec.Code)
	}
	p, err := h.st.GetProfile(*h.proxy.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	p.Responses = "block"
	if err := h.st.UpdateProfile(p); err != nil {
		t.Fatal(err)
	}
	if err := h.pol.Reload(); err != nil {
		t.Fatal(err)
	}

	if rec := h.request(http.MethodGet, testHost, "/leak", "", nil); rec.Code != http.StatusBadGateway {
		t.Fatalf("status after enabling block = %d, want 502", rec.Code)
	}
}

// Flag mode records the rule and forwards the page unchanged.
func TestResponseInspectionFlagsAndForwards(t *testing.T) {
	h := newHarness(t)
	attachProfile(t, h, model.Profile{Name: "resp-flag", Responses: "flag"})

	rec := h.request(http.MethodGet, testHost, "/leak", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), leakyBody) {
		t.Fatalf("status = %d, body = %q", rec.Code, rec.Body.String())
	}
	e := h.waitEvent(t, func(e model.Event) bool { return e.Stage == "response-waf" })
	if e.RuleID != "951230" || e.Action != "log" {
		t.Fatalf("event = %+v, want a logged 951230", e)
	}
}

func TestResponseInspectionOffLeavesResponsesAlone(t *testing.T) {
	h := newHarness(t)
	attachProfile(t, h, model.Profile{Name: "resp-off"})

	rec := h.request(http.MethodGet, testHost, "/leak", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), leakyBody) {
		t.Fatalf("status = %d, body = %q", rec.Code, rec.Body.String())
	}
	if e := h.waitEvent(t, func(e model.Event) bool { return e.Stage == "route" }); e.RuleID != "" {
		t.Fatalf("event = %+v, want a plain route event", e)
	}
}

// Every body that cannot be inspected whole is forwarded and named as skipped.
func TestResponseInspectionSkipsBodiesItCannotInspect(t *testing.T) {
	cases := []struct {
		name, reason string
		method       string
		path         string
		hdr          map[string]string
	}{
		{name: "sse", reason: "sse", method: http.MethodGet, path: "/sse"},
		{name: "range", reason: "range", method: http.MethodGet, path: "/leak", hdr: map[string]string{"Range": "bytes=0-9"}},
		{name: "encoded", reason: "encoded", method: http.MethodGet, path: "/gzip", hdr: map[string]string{"Accept-Encoding": "identity"}},
		{name: "too large", reason: "too-large", method: http.MethodGet, path: "/large"},
		{name: "head", reason: "no-body", method: http.MethodHead, path: "/leak"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			attachProfile(t, h, model.Profile{Name: "resp-skip", Responses: "block"})

			rec := h.request(tc.method, testHost, tc.path, "", tc.hdr)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want the response forwarded", rec.Code)
			}
			e := h.waitEvent(t, func(e model.Event) bool { return e.Stage == "response-skipped" })
			if e.RuleID != tc.reason {
				t.Fatalf("event = %+v, want reason %q", e, tc.reason)
			}
		})
	}
}

// The whole oversized body still reaches the client once it is passed through.
func TestResponseInspectionTooLargeDeliversEveryByte(t *testing.T) {
	h := newHarness(t)
	attachProfile(t, h, model.Profile{Name: "resp-big", Responses: "block"})

	rec := h.request(http.MethodGet, testHost, "/large", "", nil)
	if rec.Body.Len() != 200000 {
		t.Fatalf("client received %d bytes, want the full 200000", rec.Body.Len())
	}
}
