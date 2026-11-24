package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// serve runs one request through the real pipeline. The caller owns the
// synthetic parts of it: a request the HTTP server itself would reject (two
// Content-Length headers, absolute-form target) still has to be handled safely
// when it is built by something other than net/http, so it is built here.
func serve(h *harness, method, path string, edit func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Host = testHost
	req.RemoteAddr = testIP + ":43210"
	if edit != nil {
		edit(req)
	}
	rec := httptest.NewRecorder()
	h.px.ServeHTTP(rec, req)
	return rec
}

// Ambiguous framing is how request smuggling starts: the next hop and this one
// must not disagree about where a request ends, so anything ambiguous stops
// here rather than reaching an upstream.
func TestRejectsAmbiguousFraming(t *testing.T) {
	cases := []struct {
		name string
		edit func(*http.Request)
	}{
		{"duplicate content-length", func(r *http.Request) {
			r.ContentLength = 4
			r.Header.Add("Content-Length", "4")
			r.Header.Add("Content-Length", "5")
		}},
		{"content-length with transfer-encoding", func(r *http.Request) {
			r.ContentLength = 4
			r.TransferEncoding = []string{"chunked"}
		}},
		{"empty header name", func(r *http.Request) {
			r.Header[""] = []string{"smuggled"}
		}},
		{"header name with a space", func(r *http.Request) {
			r.Header["Bad Name"] = []string{"x"}
		}},
		{"absolute-form target", func(r *http.Request) {
			r.RequestURI = "http://" + testHost + "/"
		}},
		{"asterisk target", func(r *http.Request) {
			r.RequestURI = "*"
		}},
		{"h2c upgrade", func(r *http.Request) {
			r.Header.Set("Connection", "Upgrade")
			r.Header.Set("Upgrade", "h2c")
		}},
		{"upgrade on a body method", func(r *http.Request) {
			r.Header.Set("Connection", "Upgrade")
			r.Header.Set("Upgrade", "websocket")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			before := h.hits.Load()
			rec := serve(h, http.MethodPost, "/", tc.edit)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if after := h.hits.Load(); after != before {
				t.Fatalf("the request reached the upstream %d times", after-before)
			}
		})
	}
}

// TRACE is refused by the policy layer rather than by a rule, and the refusal
// has to land before the upstream sees anything: a reflective TRACE is how
// cross-site tracing reads a cookie back out of a request.
func TestTraceIsRefused(t *testing.T) {
	h := newHarness(t)
	rec := serve(h, http.MethodTrace, "/", nil)
	// Either layer may refuse it first: the protocol stage rejects a method it
	// does not carry, the policy stage refuses TRACE by name.
	if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 or 405: %s", rec.Code, rec.Body.String())
	}
	if hits := h.hits.Load(); hits != 0 {
		t.Fatalf("a TRACE request reached the upstream %d times", hits)
	}
}

// HTTP/0.9 has neither headers nor a Host, so a listener that accepted it would
// forward a request no policy layer can evaluate. The server has to refuse it
// before the pipeline, and nothing may reach the upstream either way.
func TestHTTP09RequestIsRefused(t *testing.T) {
	h := newHarness(t)
	srv := httptest.NewServer(h.px)
	defer srv.Close()
	for _, raw := range []string{"GET /etc/passwd\r\n\r\n", "GET /etc/passwd HTTP/0.9\r\n\r\n"} {
		conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(conn, raw); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		line, _ := bufio.NewReader(conn).ReadString('\n')
		_ = conn.Close()
		if strings.Contains(line, "200") {
			t.Fatalf("%q was answered with %q", raw, strings.TrimSpace(line))
		}
	}
	if hits := h.hits.Load(); hits != 0 {
		t.Fatalf("an HTTP/0.9 request reached the upstream %d times", hits)
	}
}

// A fragment character is part of the path once it arrives percent-encoded, and
// it must survive the rewrite: re-encoding it as a separator would route the
// request somewhere else.
func TestHashInPathSurvivesForwarding(t *testing.T) {
	h := newHarness(t)
	rec := h.request(http.MethodGet, testHost, "/a%23frag/b", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "upstream:/a#frag/b:") {
		t.Fatalf("upstream saw %q", rec.Body.String())
	}
}

// The checks a path-based rule makes have to see the same path the upstream
// would resolve. A decoy reached through a dot segment proves they do.
func TestDotSegmentsAreScreenedBeforeDecoys(t *testing.T) {
	h := newHarness(t)
	rec := h.request(http.MethodGet, testHost, "/nothing/../.env", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 from the decoy rule", rec.Code)
	}
	// The ban is written off the request path, so give it a moment to land.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := h.bans.Match(netip.MustParseAddr(testIP)); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a decoy hit through a dot segment did not ban")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A WebSocket upgrade is the one protocol switch the pipeline supports, so the
// 101 has to reach the client with the connection usable afterwards.
func TestWebSocketUpgradeReachesTheClient(t *testing.T) {
	h := newHarness(t)
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
	echo := make([]byte, 5)
	if _, err := br.Read(echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != "ws-yo" {
		t.Fatalf("tunnel carried %q, want %q", echo, "ws-yo")
	}
	// The request is logged once the tunnelled connection ends, and the event
	// must record the 101 the client actually received.
	_ = conn.Close()
	e := h.waitEvent(t, func(e model.Event) bool { return e.Path == "/ws" })
	if e.Status != http.StatusSwitchingProtocols {
		t.Fatalf("event status = %d, want 101", e.Status)
	}
}
