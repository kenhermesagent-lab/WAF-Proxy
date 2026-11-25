package proxy

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/clientip"
)

// requestScheme drives the pipeline with or without TLS on this listener and
// returns the scheme the upstream was handed.
func (h *harness) requestScheme(t *testing.T, src string, tlsOn bool, hdr map[string]string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/proto", nil)
	req.Host = testHost
	req.URL.Host = testHost
	if tlsOn {
		req.TLS = &tls.ConnectionState{}
		req.URL.Scheme = "https"
	}
	req.RemoteAddr = src + ":43210"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.px.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

// A site served over TLS tells the app so, which is what Seafile's CSRF origin
// check and any absolute URL built from the request rely on.
func TestUpstreamSeesTheListenerScheme(t *testing.T) {
	h := newHarness(t)
	if got := h.requestScheme(t, testIP, true, nil); got != "proto:https" {
		t.Fatalf("upstream saw %q, want proto:https", got)
	}
	if got := h.requestScheme(t, testIP, false, nil); got != "proto:http" {
		t.Fatalf("upstream saw %q, want proto:http", got)
	}
}

// A front proxy that terminated TLS leaves this listener a plain hop. Its
// X-Forwarded-Proto is believed only because the peer is in the allowlist.
func TestTrustedFrontProxySuppliesTheScheme(t *testing.T) {
	h := newHarness(t)
	r, err := clientip.New([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	h.px.d.ClientIP = r

	got := h.requestScheme(t, "10.0.0.2", false, map[string]string{
		"X-Forwarded-Proto": "https",
	})
	if got != "proto:https" {
		t.Fatalf("upstream saw %q, want the scheme the trusted proxy named", got)
	}
}

// A client cannot claim HTTPS on a plain hop, and an untrusted proxy cannot do
// it either: the browser's own connection decides.
func TestUntrustedPeerCannotClaimTheScheme(t *testing.T) {
	h := newHarness(t)
	r, err := clientip.New([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	h.px.d.ClientIP = r

	got := h.requestScheme(t, "198.51.100.7", false, map[string]string{
		"X-Forwarded-Proto": "https",
	})
	if got != "proto:http" {
		t.Fatalf("upstream saw %q, want proto:http", got)
	}
}
