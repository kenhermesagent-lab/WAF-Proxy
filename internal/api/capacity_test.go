package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// addRoute creates a proxy and builds it into the running edge, which is what
// the capacity report reads.
func addRoute(t *testing.T, srv *Server, hostname string) {
	t.Helper()
	if _, err := srv.st.CreateProxy(&model.Proxy{Hostname: hostname, Enabled: true, GateMode: "off", WAFMode: "off"}); err != nil {
		t.Fatal(err)
	}
	if err := srv.proxy.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// The capacity endpoint is the console's only view of the budget, the cache and
// the refusals, and a tenant console must not see another site's routes.
func TestCapacityEndpointShapeAndScoping(t *testing.T) {
	srv, token, _ := newSettingsServer(t)
	addRoute(t, srv, "default.test")
	if _, err := srv.st.CreateSite("tenant", "Tenant", "console.tenant.test"); err != nil {
		t.Fatal(err)
	}

	read := func(slug string) map[string]any {
		rec := sitesCall(srv, "gui.local", http.MethodGet, "/api/capacity", token, "", slug, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%q capacity = %d: %s", slug, rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	host := read("")
	for _, key := range []string{"inflight", "max_inflight", "queued", "buffer_bytes",
		"max_buffer_bytes", "shed", "cache", "sites", "pools", "heap_bytes", "gc_cycles", "memory_limit"} {
		if _, ok := host[key]; !ok {
			t.Fatalf("capacity response has no %q: %v", key, host)
		}
	}
	hostSites, _ := host["sites"].([]any)
	if len(hostSites) != 1 || hostSites[0].(map[string]any)["host"] != "default.test" {
		t.Fatalf("host capacity lists %v, want default.test", hostSites)
	}

	tenantSites, _ := read("tenant")["sites"].([]any)
	if len(tenantSites) != 0 {
		t.Fatalf("tenant capacity lists another site's route: %v", tenantSites)
	}
}

func TestPrometheusMetricsIncludeCapacity(t *testing.T) {
	srv, _, _ := newSettingsServer(t)
	addRoute(t, srv, "default.test")
	srv.cfg.MetricsToken = "a-metrics-scrape-token-that-is-long-enough"
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+srv.cfg.MetricsToken)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{
		"wafproxy_inflight_requests ",
		"wafproxy_queued_requests ",
		"wafproxy_buffer_bytes ",
		`wafproxy_shed_total{reason="queue"} `,
		`wafproxy_shed_total{reason="client"} `,
		`wafproxy_cache_bytes{site="default.test"} `,
		`wafproxy_cache_hits_total{site="default.test"} `,
		`wafproxy_cache_misses_total{site="default.test"} `,
		"wafproxy_heap_bytes ",
		"wafproxy_gc_cycles_total ",
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("metrics missing %q:\n%s", want, rec.Body.String())
		}
	}
}
