package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

// A protocol switch must pass through: the client needs the 101 and the raw
// connection, not a buffered page.
func TestResponseInspectionLeavesUpgradeUntouched(t *testing.T) {
	h := newHarness(t)
	attachProfile(t, h, model.Profile{Name: "resp-ws", Responses: "block"})

	srv := httptest.NewServer(h.px)
	defer srv.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", testHost)

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("status line = %q, want a 101", strings.TrimSpace(status))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	rest := make([]byte, 5)
	if _, err := io.ReadFull(br, rest); err != nil {
		t.Fatalf("reading the switched protocol: %v", err)
	}
	if string(rest) != "ws-yo" {
		t.Fatalf("switched protocol payload = %q, want ws-yo", rest)
	}
	// The request is only logged once the tunnelled connection ends.
	_ = conn.Close()
	e := h.waitEvent(t, func(e model.Event) bool { return e.Stage == "response-skipped" })
	if e.RuleID != "upgrade" || e.Action != "allow" {
		t.Fatalf("event = %+v, want an allowed response-skipped upgrade", e)
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
