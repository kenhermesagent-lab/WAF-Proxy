package api

import (
	"net/http"
	"testing"
)

func TestStandbyAllows(t *testing.T) {
	cases := []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodGet, "/api/proxies", true},
		{http.MethodHead, "/api/health", true},
		{http.MethodPost, "/api/proxies", false},
		{http.MethodPut, "/api/settings", false},
		{http.MethodDelete, "/api/bans/1", false},
		{http.MethodPost, "/api/ha/failover", true},
		{http.MethodPost, "/api/logout", true},
		{http.MethodPost, "/api/account/totp", true},
		{http.MethodPost, "/api/login", true},
	}
	for _, tc := range cases {
		if got := standbyAllows(tc.method, tc.path); got != tc.want {
			t.Errorf("standbyAllows(%s, %s) = %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}
