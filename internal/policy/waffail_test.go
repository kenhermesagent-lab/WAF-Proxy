package policy

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

// An allow here would be a WAF silently switched off for every request it
// could not judge, so a set with no compiled engine has to refuse.
func TestMissingWAFEngineFailsClosed(t *testing.T) {
	pol, _, _ := newEngine(t)
	pol.wafs = &waf.Set{}
	id := int64(1)
	proxy := &model.Proxy{Hostname: "app.example.com", Enabled: true, WAFMode: "block", ProfileID: &id}
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)

	verdict, _ := pol.Inspect(&Request{
		Proxy: proxy, Addr: netip.MustParseAddr("203.0.113.9"), Method: http.MethodGet, HTTP: req,
	})
	if verdict.Action != "block" || verdict.Status != http.StatusServiceUnavailable || verdict.Rule != "200010" {
		t.Fatalf("verdict = %+v, want a fail-closed 503", verdict)
	}
}
