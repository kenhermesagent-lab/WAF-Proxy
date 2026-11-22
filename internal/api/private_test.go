package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTailscaleOnly(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := TailscaleOnly(ok)
	cases := []struct {
		remote string
		want   int
	}{
		{"100.64.0.1:5000", http.StatusNoContent},
		{"100.127.255.254:5000", http.StatusNoContent},
		{"192.168.1.5:5000", http.StatusForbidden},
		{"10.0.0.5:5000", http.StatusForbidden},
		{"203.0.113.9:5000", http.StatusForbidden},
		{"100.63.255.255:5000", http.StatusForbidden},
		{"100.128.0.1:5000", http.StatusForbidden},
		{"[fd7a:115c:a1e0::1]:5000", http.StatusForbidden},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = tc.remote
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("RemoteAddr %q: status = %d, want %d", tc.remote, rec.Code, tc.want)
		}
	}
}

func TestPrivateNetworksOnly(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := PrivateNetworksOnly(ok)

	cases := []struct {
		remote string
		want   int
	}{
		{"10.0.0.10:5000", http.StatusNoContent},
		{"10.20.30.40:5000", http.StatusNoContent},
		{"172.16.0.5:5000", http.StatusNoContent},
		{"172.31.255.5:5000", http.StatusNoContent},
		{"127.0.0.1:5000", http.StatusNoContent},
		{"[::1]:5000", http.StatusNoContent},
		{"[::ffff:192.168.1.5]:5000", http.StatusNoContent},
		{"203.0.113.9:5000", http.StatusForbidden},
		{"172.32.0.5:5000", http.StatusForbidden},
		{"100.64.0.5:5000", http.StatusForbidden},
		{"169.254.1.5:5000", http.StatusForbidden},
		{"[2001:db8::1]:5000", http.StatusForbidden},
		{"[fd00::1]:5000", http.StatusForbidden},
		{"not-an-address", http.StatusForbidden},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = tc.remote
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("RemoteAddr %q: status = %d, want %d", tc.remote, rec.Code, tc.want)
		}
	}
}
