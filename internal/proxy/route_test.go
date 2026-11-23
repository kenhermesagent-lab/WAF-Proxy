package proxy

import (
	"net/http"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func request(method, target string, header http.Header) *http.Request {
	r, _ := http.NewRequest(method, target, nil)
	if header != nil {
		r.Header = header
	}
	return r
}

func TestMatchRouteRequiresEveryMatcher(t *testing.T) {
	routes := []model.Route{
		{Kind: model.RouteAlias, Match: "/api", Method: http.MethodPost, Header: "X-Tenant: blue",
			Query: "v=2", Target: "/v2/api"},
	}
	if _, _, ok := MatchRoute(request(http.MethodGet, "/api/x?v=2", http.Header{"X-Tenant": {"blue"}}), routes); ok {
		t.Fatal("a GET matched a POST-only route")
	}
	if _, _, ok := MatchRoute(request(http.MethodPost, "/api/x?v=2", http.Header{"X-Tenant": {"red"}}), routes); ok {
		t.Fatal("a route matched the wrong header value")
	}
	if _, _, ok := MatchRoute(request(http.MethodPost, "/api/x?v=1", http.Header{"X-Tenant": {"blue"}}), routes); ok {
		t.Fatal("a route matched the wrong query")
	}
	_, target, ok := MatchRoute(request(http.MethodPost, "/api/x?v=2", http.Header{"X-Tenant": {"blue"}}), routes)
	if !ok || target != "/v2/api/x" {
		t.Fatalf("matched route produced target %q (ok=%v)", target, ok)
	}
}

func TestMatchRouteRegexRewritesWithCaptureGroups(t *testing.T) {
	routes := []model.Route{{Kind: model.RouteAlias, Match: `^/old/(.*)$`, Target: "/new/$1", Regex: true}}
	_, target, ok := MatchRoute(request(http.MethodGet, "/old/a/b", nil), routes)
	if !ok || target != "/new/a/b" {
		t.Fatalf("regex rewrite produced %q (ok=%v)", target, ok)
	}
	bad := []model.Route{{Kind: model.RouteAlias, Match: `^(unclosed`, Regex: true, Target: "/x"}}
	if _, _, ok := MatchRoute(request(http.MethodGet, "/anything", nil), bad); ok {
		t.Fatal("an invalid regex matched")
	}
}

func TestMatchRouteUsesOrderForPriority(t *testing.T) {
	routes := []model.Route{
		{Kind: model.RouteAlias, Match: "/api", Target: "/first"},
		{Kind: model.RouteAlias, Match: "/api/deep", Target: "/second"},
	}
	rt, _, ok := MatchRoute(request(http.MethodGet, "/api/deep/x", nil), routes)
	if !ok || rt.Target != "/first" {
		t.Fatalf("first listed route not chosen: %+v", rt)
	}
}

func TestMatchRouteCarriesRedirectStatusAndUpstream(t *testing.T) {
	routes := []model.Route{{
		Kind: model.RouteRedirect, Match: "/old", Target: "https://new.example.com$path",
		Status: http.StatusPermanentRedirect, Upstream: "http://10.0.0.5:8080", Timeout: 15,
	}}
	rt, target, ok := MatchRoute(request(http.MethodGet, "/old/page", nil), routes)
	if !ok || target != "https://new.example.com/old/page" {
		t.Fatalf("redirect target %q (ok=%v)", target, ok)
	}
	if rt.Status != http.StatusPermanentRedirect || rt.Timeout != 15 || rt.Upstream == "" {
		t.Fatalf("route fields lost: %+v", rt)
	}
}

func TestRouteForIgnoresRequestOnlyMatchers(t *testing.T) {
	routes := []model.Route{{Kind: model.RouteAlias, Match: "/x", Method: http.MethodPost, Target: "/y"}}
	if _, _, ok := RouteFor(routes, "/x"); ok {
		t.Fatal("RouteFor matched a POST-only route for its synthetic GET")
	}
}
