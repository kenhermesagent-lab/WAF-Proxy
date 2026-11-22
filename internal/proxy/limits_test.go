package proxy

import (
	"context"
	"net/http"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// attachProfile stores a WAF profile and points the harness proxy at it, then
// reloads both engines the way the console does after a save.
func attachProfile(t *testing.T, h *harness, p model.Profile) {
	t.Helper()
	if p.Mode == "" {
		p.Mode = "block"
	}
	if err := h.st.CreateProfile(&p); err != nil {
		t.Fatal(err)
	}
	h.proxy.ProfileID = &p.ID
	if err := h.st.UpdateProxy(&h.proxy); err != nil {
		t.Fatal(err)
	}
	if err := h.pol.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := h.px.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// A response that declares a length above the ceiling is refused outright: the
// operator gets an error instead of a half-download.
func TestResponseCeilingRefusesDeclaredLength(t *testing.T) {
	h := newHarness(t)
	attachProfile(t, h, model.Profile{Name: "capped", MaxResponse: 64 << 10, MaxBody: 1 << 20})

	rec := h.request(http.MethodGet, testHost, "/large", "", nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for a 200 kB body under a 64 KiB ceiling", rec.Code)
	}
	if e := h.waitEvent(t, func(e model.Event) bool { return e.Stage == "response-cap" }); e.RuleID != "too-large" {
		t.Fatalf("event = %+v, want a response-cap event", e)
	}
}

// A streamed response has no length to check, so it is cut when it passes and
// the operator can see that it happened.
func TestResponseCeilingCutsStreamedBody(t *testing.T) {
	h := newHarness(t)
	attachProfile(t, h, model.Profile{Name: "capped", MaxResponse: 64 << 10, MaxBody: 1 << 20})

	rec := h.request(http.MethodGet, testHost, "/stream", "", nil)
	if got := rec.Body.Len(); got > 64<<10 {
		t.Fatalf("client received %d bytes, want at most 65536", got)
	}
	if e := h.waitEvent(t, func(e model.Event) bool { return e.Stage == "response-cap" }); e.RuleID != "too-large" {
		t.Fatalf("event = %+v, want a response-cap event", e)
	}
}

func TestLoginPathsAreThrottledBeforeTheApp(t *testing.T) {
	h := newHarness(t)
	attachProfile(t, h, model.Profile{Name: "logins", LoginPaths: "/login,/api/session", LoginRPS: 1, LoginBurst: 1})

	if rec := h.request(http.MethodPost, testHost, "/login", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("first attempt = %d, want 200", rec.Code)
	}
	rec := h.request(http.MethodPost, testHost, "/login", "", nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second attempt = %d, want 429", rec.Code)
	}
	// The limit is per path: unrelated traffic is not throttled with it.
	if rec := h.request(http.MethodGet, testHost, "/index.html", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("unrelated path = %d, want 200", rec.Code)
	}
}

func TestAdminPathsAreRestrictedToTheAllowlist(t *testing.T) {
	h := newHarness(t)
	attachProfile(t, h, model.Profile{
		Name: "admin", AdminPaths: "/admin,/config", AdminIPs: "10.0.0.0/8,192.168.0.0/16",
	})

	rec := h.request(http.MethodGet, testHost, "/admin/users", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("admin path from an outside address = %d, want 403", rec.Code)
	}
	if e := h.waitEvent(t, func(e model.Event) bool { return e.Stage == "admin-path" }); e.Action != "block" {
		t.Fatalf("event = %+v, want a block", e)
	}
	if rec := h.request(http.MethodGet, testHost, "/public", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("public path = %d, want 200", rec.Code)
	}

	// The same profile with the test address allowed lets the path through.
	h.proxy.ProfileID = nil
	attachProfile(t, h, model.Profile{
		Name: "admin-local", AdminPaths: "/admin", AdminIPs: "203.0.113.0/24",
	})
	if rec := h.request(http.MethodGet, testHost, "/admin/users", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("admin path from an allowlisted address = %d, want 200", rec.Code)
	}
}
