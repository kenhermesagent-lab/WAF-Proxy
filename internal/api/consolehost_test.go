package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConsoleHostsAcceptsOnlyConfiguredHosts(t *testing.T) {
	handler := ConsoleHosts([]string{"admin.example", "WAF.Internal"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	cases := []struct {
		host string
		want int
	}{
		{"127.0.0.1:8080", http.StatusNoContent},
		{"127.0.0.1", http.StatusNoContent},
		{"[::1]:8080", http.StatusNoContent},
		{"[::1]", http.StatusNoContent},
		{"localhost:8080", http.StatusNoContent},
		{"LOCALHOST", http.StatusNoContent},
		{"admin.example", http.StatusNoContent},
		{"admin.example:8443", http.StatusNoContent},
		{"admin.example.", http.StatusNoContent},
		{"waf.internal:8443", http.StatusNoContent},
		// A rebound name resolves to this host but is not one it answers to.
		{"evil.example", http.StatusForbidden},
		{"evil.example:8443", http.StatusForbidden},
		{"admin.example.evil.example", http.StatusForbidden},
		{"", http.StatusForbidden},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
		req.Host = tc.host
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("Host %q: status = %d, want %d", tc.host, rec.Code, tc.want)
		}
	}
}
