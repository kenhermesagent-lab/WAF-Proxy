package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/clientip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/config"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// trustedResolver parses the allowlist through the real configuration path, so
// the test fails if the environment variable stops reaching the resolver.
func trustedResolver(t *testing.T, cidrs string) *clientip.Resolver {
	t.Helper()
	t.Setenv("WAFPROXY_TRUSTED_PROXIES", cidrs)
	t.Setenv("WAFPROXY_DATA_DIR", t.TempDir())
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	r, err := clientip.New(cfg.TrustedProxies)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// fronting starts the proxy behind a real HTTP proxy, the way Caddy or a tunnel
// sits in front of it. The fronting hop appends the address it saw to
// X-Forwarded-For, and the test client states the address it wants to be seen
// as in X-Test-Client, so the header reads "claimed, fronting-peer".
func fronting(t *testing.T, h *harness) *httptest.Server {
	t.Helper()
	backend := httptest.NewServer(h.px)
	t.Cleanup(backend.Close)
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if claimed := r.Header.Get("X-Test-Client"); claimed != "" {
			r.Header.Set("X-Forwarded-For", claimed)
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func viaFront(t *testing.T, srv *httptest.Server, path, claimed string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The fronting proxies preserve Host, so routing has to see the site name.
	req.Host = testHost
	if claimed != "" {
		req.Header.Set("X-Test-Client", claimed)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// The address a trusted fronting proxy names is the one the access profile and
// the ban engine act on, not the loopback address the tunnel connects from.
func TestTrustedFrontSeesRealClientInDecisions(t *testing.T) {
	h := newHarness(t)
	h.px.d.ClientIP = trustedResolver(t, "127.0.0.1")

	// A profile that admits only 198.51.100.20 narrows the site to that address.
	// Two allowed clients, so one can be banned without removing the other.
	allowed, err := h.st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyIPWhitelist, Value: "198.51.100.20",
		Action: "allow", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyIPWhitelist, Value: "198.51.100.21",
		Action: "allow", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	profile := &model.AccessProfile{
		Name:  "tunnel",
		Rules: []model.AccessRule{{PolicyID: allowed, Role: "allow"}, {PolicyID: second, Role: "allow"}},
	}
	if err := h.st.CreateAccessProfile(profile); err != nil {
		t.Fatal(err)
	}
	h.proxy.AccessProfileID = &profile.ID
	if err := h.st.UpdateProxy(&h.proxy); err != nil {
		t.Fatal(err)
	}
	// The engine caches profiles, so it has to reload before the edge does.
	if err := h.pol.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := h.px.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	srv := fronting(t, h)
	if code, body := viaFront(t, srv, "/", "198.51.100.20"); code != http.StatusOK {
		t.Fatalf("allowed client through the tunnel = %d %q, want 200", code, body)
	}
	if code, body := viaFront(t, srv, "/", "203.0.113.77"); code != http.StatusForbidden {
		t.Fatalf("client outside the profile = %d %q, want 403", code, body)
	}

	// The upstream receives the real client, so backends log and rate-limit it.
	if _, body := viaFront(t, srv, "/echo", "198.51.100.20"); !strings.Contains(body, "upstream:/echo:198.51.100.20") {
		t.Fatalf("upstream did not see the real client: %q", body)
	}
	if e := h.waitEvent(t, func(e model.Event) bool { return e.Path == "/echo" }); e.SrcIP != "198.51.100.20" {
		t.Fatalf("event source = %q, want 198.51.100.20", e.SrcIP)
	}

	// The ban engine judges the same address: a ban on one client fires through
	// the tunnel and leaves the other one alone. A ban keyed on the tunnel's own
	// address would refuse both.
	if _, err := h.bans.Add("198.51.100.20", "test ban", "manual", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	if code, body := viaFront(t, srv, "/", "198.51.100.20"); code != http.StatusForbidden {
		t.Fatalf("banned client through the tunnel = %d %q, want 403", code, body)
	}
	if code, body := viaFront(t, srv, "/", "198.51.100.21"); code != http.StatusOK {
		t.Fatalf("the ban caught an unrelated client: %d %q", code, body)
	}
	if _, err := h.bans.Add("127.0.0.1", "tunnel ban", "manual", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	if code, body := viaFront(t, srv, "/", "198.51.100.21"); code != http.StatusOK {
		t.Fatalf("a ban on the tunnel address refused the real client: %d %q", code, body)
	}
}

// A hop that is not in the allowlist cannot name the client, however it fills
// in the header.
func TestUntrustedFrontIsStillOverwritten(t *testing.T) {
	h := newHarness(t)
	h.px.d.ClientIP = trustedResolver(t, "10.0.0.0/8")

	srv := fronting(t, h)
	if code, body := viaFront(t, srv, "/echo", "198.51.100.20"); code != http.StatusOK ||
		!strings.Contains(body, "upstream:/echo:127.0.0.1") {
		t.Fatalf("untrusted hop named the client: %d %q", code, body)
	}

	// A ban on the claimed address must not touch the real sender, and a ban on
	// the sender must apply.
	if _, err := h.bans.Add("198.51.100.20", "test ban", "manual", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	if code, body := viaFront(t, srv, "/echo", "198.51.100.20"); code != http.StatusOK {
		t.Fatalf("a ban on an untrusted header blocked the request: %d %q", code, body)
	}
}
