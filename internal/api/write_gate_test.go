package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWriteGatePausesMutations covers the quiesce gate a planned move sets on
// the node that is about to be drained: writes are refused with a reason, reads
// keep working, and opening the gate restores writes.
func TestWriteGatePausesMutations(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	srv.SetWriteGate(func() bool { return true })

	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/bans",
			strings.NewReader(`{"cidr":"203.0.113.44","reason":"gate test"}`))
		req.Host = "gui.local"
		req.RemoteAddr = "10.0.0.10:5000"
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		req.Header.Set("X-CSRF-Token", csrf)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	if rec := post(); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "paused") {
		t.Fatalf("gated POST = %d: %s", rec.Code, rec.Body.String())
	}

	get := httptest.NewRequest(http.MethodGet, "/api/bans", nil)
	get.Host = "gui.local"
	get.RemoteAddr = "10.0.0.10:5000"
	get.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, get)
	if rec.Code != http.StatusOK {
		t.Fatalf("gated GET = %d: %s", rec.Code, rec.Body.String())
	}

	if n := srv.ConfigWritesInFlight(); n != 0 {
		t.Fatalf("writes in flight after the requests = %d, want 0", n)
	}

	srv.SetWriteGate(func() bool { return false })
	if rec := post(); rec.Code != http.StatusCreated {
		t.Fatalf("POST after opening the gate = %d: %s", rec.Code, rec.Body.String())
	}
}
