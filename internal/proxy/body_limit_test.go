package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// A body above the old 8 MiB ceiling is forwarded once the operator raises the
// limit: the ceiling is a setting, not a property of the buffering code.
func TestRaisedBodyLimitForwardsLargeBody(t *testing.T) {
	h := newHarness(t)
	h.px.SetBodyLimit(16 << 20)

	body := strings.Repeat("a", 9<<20)
	rec := h.request(http.MethodPost, testHost, "/upload", body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a 9 MiB body under a 16 MiB limit", rec.Code)
	}
	if h.hits.Load() != 1 {
		t.Fatalf("upstream hits = %d, want 1", h.hits.Load())
	}
}

// A body with no declared length is charged to the buffer budget as it arrives.
// Without that charge a raised max_body would let one chunked request allocate
// up to the ceiling while only its 64 KiB estimate is accounted for.
func TestChunkedBodyIsChargedToTheBudget(t *testing.T) {
	h := newHarness(t)
	h.px.SetBodyLimit(16 << 20)
	h.px.SetBudget(64<<10, 0)

	rec := h.chunkedRequest(http.MethodPost, "/upload", strings.Repeat("a", 256<<10))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when a chunked body passes the buffer budget", rec.Code)
	}
	if h.hits.Load() != 0 {
		t.Fatal("an over-budget body reached the upstream")
	}
	if e := h.waitEvent(t, func(e model.Event) bool { return e.RuleID == "budget-too-large" }); e.Stage != "capacity" {
		t.Fatalf("event = %+v, want a capacity refusal", e)
	}
}

// chunkedRequest sends a body with no Content-Length, the way a streaming client
// does, so the reservation is the 64 KiB estimate rather than the real size.
func (h *harness) chunkedRequest(method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Body = io.NopCloser(strings.NewReader(body))
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	req.Host = testHost
	req.URL.Scheme = "https"
	req.URL.Host = testHost
	req.TLS = &tls.ConnectionState{}
	req.RemoteAddr = testIP + ":43210"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.px.ServeHTTP(rec, req)
	return rec
}
