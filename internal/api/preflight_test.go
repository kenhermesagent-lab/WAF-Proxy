package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func eventFixture() model.Event {
	return model.Event{
		SrcIP: "203.0.113.7", Country: "RU", ASN: 64500,
		Host: "app.example.com", Method: "GET", Path: "/./.env", Action: "ban", Stage: "decoy",
	}
}

func postJSON(t *testing.T, srv *Server, token, csrf, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Host = "gui.local"
	req.RemoteAddr = "10.0.0.10:5000"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
}

func TestPolicyEventMatcher(t *testing.T) {
	event := eventFixture()

	cases := []struct {
		name  string
		kind  string
		value string
		want  bool
	}{
		{"exact address", "ip_blacklist", "203.0.113.7", true},
		{"cidr contains", "ip_blacklist", "203.0.113.0/24", true},
		{"outside cidr", "ip_whitelist", "198.51.100.0/24", false},
		{"country", "country_blacklist", "RU", true},
		{"country case", "country_blacklist", "ru", true},
		{"other country", "country_whitelist", "DE", false},
		{"asn", "asn_block", "64500", true},
		{"other asn", "asn_block", "64501", false},
		{"decoy exact", "decoy", "/.env", true},
		{"decoy canonical", "decoy", "/./.env", true},
		{"decoy trailing slash", "decoy", "/.env/", true},
		{"decoy miss", "decoy", "/wp-login.php", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := policyEventMatcher(c.kind, c.value)(event); got != c.want {
				t.Fatalf("match(%s, %q) = %v, want %v", c.kind, c.value, got, c.want)
			}
		})
	}
}

// A value the engine cannot parse must match nothing instead of panicking.
func TestPolicyEventMatcherIgnoresGarbage(t *testing.T) {
	event := eventFixture()
	for _, kind := range []string{"ip_blacklist", "country_blacklist", "asn_block", "decoy", "rate_limit"} {
		if policyEventMatcher(kind, "not-a-rule")(event) {
			t.Fatalf("match(%s, not-a-rule) = true", kind)
		}
	}
}

func TestPreflightCountsServedAndRefused(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)

	rec := postJSON(t, srv, token, csrf, "/api/policies/preflight", `{"kind":"country_blacklist","value":"RU"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var out preflightResult
	decodeJSON(t, rec, &out)
	// The fixture logs one served request and one decoy ban, both from RU.
	if out.Matched != 2 || out.Allowed != 1 || out.Blocked != 1 {
		t.Fatalf("unexpected counts: %+v", out)
	}
	if out.Addresses != 1 || len(out.Samples) != 2 || out.Hours != 24 {
		t.Fatalf("unexpected shape: %+v", out)
	}
	if len(out.Hosts) != 1 || out.Hosts[0] != "app.example.com" {
		t.Fatalf("unexpected hosts: %+v", out.Hosts)
	}
}

func TestPreflightRejectsInvalidKindAndValue(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	if rec := postJSON(t, srv, token, csrf, "/api/policies/preflight", `{"kind":"nope","value":"RU"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown kind status = %d", rec.Code)
	}
	if rec := postJSON(t, srv, token, csrf, "/api/policies/preflight", `{"kind":"ip_blacklist","value":"not-an-ip"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad cidr status = %d", rec.Code)
	}
}

func TestPreflightRateLimitIsExplained(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	rec := postJSON(t, srv, token, csrf, "/api/policies/preflight", `{"kind":"rate_limit","value":"40/80"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var out preflightResult
	decodeJSON(t, rec, &out)
	if len(out.Notes) == 0 || out.Scanned != 0 {
		t.Fatalf("rate limit preflight should only explain itself: %+v", out)
	}
}
