package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthProviderValidation(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/auth-providers", strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		req.Header.Set("X-CSRF-Token", csrf)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	cases := []struct{ name, body, want string }{
		{"no name", `{"kind":"authelia","verify_url":"http://authelia:9091/api/verify"}`, "name"},
		{"unknown kind", `{"name":"x","kind":"keycloak","verify_url":"http://a/b"}`, "kind"},
		{"relative url", `{"name":"x","kind":"authelia","verify_url":"/api/verify"}`, "absolute"},
		{"bad login url", `{"name":"x","kind":"authelia","verify_url":"http://a/b","login_url":"javascript:alert(1)"}`, "absolute"},
	}
	for _, tc := range cases {
		rec := post(tc.body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (%s)", tc.name, rec.Code, rec.Body)
			continue
		}
		if !strings.Contains(strings.ToLower(rec.Body.String()), tc.want) {
			t.Errorf("%s: message %q does not mention %q", tc.name, rec.Body, tc.want)
		}
	}

	rec := post(`{"name":"Home","kind":"authentik","verify_url":"http://authentik:9000/outpost.goauthentik.io/auth/traefik","login_url":"https://authentik.example.com","secret":"shared"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid provider rejected: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "shared") {
		t.Fatalf("the sealed secret was echoed back: %s", rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"has_secret":true`) {
		t.Fatalf("has_secret missing: %s", rec.Body)
	}
}

func TestForwardAuthProxyRequiresAProvider(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	if err := srv.st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/proxies", strings.NewReader(
		`{"hostname":"app.example.com","gate_mode":"forward_auth","upstreams":[{"url":"http://10.0.0.5:8080","weight":1,"enabled":true}]}`))
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "identity provider") {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
}
