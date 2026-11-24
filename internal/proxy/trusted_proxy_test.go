package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/clientip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// With the fronting proxy trusted, the client it names reaches the upstream and
// the access log, which is what the access lists and ban engine act on.
func TestTrustedProxySuppliesClientAddress(t *testing.T) {
	h := newHarness(t)
	r, err := clientip.New([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	h.px.d.ClientIP = r

	rec := h.request(http.MethodGet, testHost, "/echo", "", map[string]string{
		"X-Forwarded-For": "198.51.100.20",
		"X-Real-Ip":       "1.2.3.4",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "upstream:/echo:198.51.100.20") {
		t.Fatalf("upstream saw %q, want the client named by the trusted proxy", rec.Body.String())
	}
	if e := h.waitEvent(t, func(e model.Event) bool { return e.Path == "/echo" }); e.SrcIP != "198.51.100.20" {
		t.Fatalf("event source = %q, want 198.51.100.20", e.SrcIP)
	}
}

// A peer outside the allowlist cannot name itself, even with a resolver set.
func TestUntrustedPeerCannotSetClientAddress(t *testing.T) {
	h := newHarness(t)
	r, err := clientip.New([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	h.px.d.ClientIP = r

	rec := h.request(http.MethodGet, testHost, "/echo", "", map[string]string{
		"X-Forwarded-For": "198.51.100.20",
	})
	if !strings.Contains(rec.Body.String(), "upstream:/echo:"+testIP) {
		t.Fatalf("untrusted peer set the client address: %q", rec.Body.String())
	}
}

// The budget is a hard ceiling: past it, requests are refused instead of
// buffering more bodies in memory.
func TestInflightBudgetSheds(t *testing.T) {
	s := &Server{}
	s.SetMaxInflight(2)
	first := s.acquire()
	second := s.acquire()
	if !first || !second {
		t.Fatal("the budget refused a request it should accept")
	}
	if s.acquire() {
		t.Fatal("a third request was accepted over a budget of two")
	}
	inflight, max, shed := s.Capacity()
	if inflight != 2 || max != 2 || shed != 1 {
		t.Fatalf("capacity = %d/%d shed %d, want 2/2 shed 1", inflight, max, shed)
	}
	s.release()
	if inflight, _, _ := s.Capacity(); inflight != 1 {
		t.Fatalf("inflight = %d after release, want 1", inflight)
	}
}

// A request past the budget is refused at the door, with a retry hint, instead
// of being buffered behind the slow ones.
func TestShedRequestGets503(t *testing.T) {
	s := &Server{}
	s.SetMaxInflight(1)
	s.inflight <- struct{}{} // the budget is already taken
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = testHost
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("a refused request carries no Retry-After")
	}
	if _, _, shed := s.Capacity(); shed != 1 {
		t.Fatalf("shed counter = %d, want 1", shed)
	}
}
