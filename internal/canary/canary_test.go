package canary

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunNamesTheFailingStage(t *testing.T) {
	cases := []struct {
		name   string
		status int
		failed string
	}{
		{"healthy", http.StatusOK, ""},
		{"waf block", http.StatusForbidden, "waf"},
		{"rate limit", http.StatusTooManyRequests, "waf"},
		{"routing", http.StatusMisdirectedRequest, "route"},
		{"upstream down", http.StatusBadGateway, "upstream"},
		{"upstream error", http.StatusInternalServerError, "upstream"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != Path {
					t.Errorf("probe path = %q", r.URL.Path)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("canary"))
			}))
			defer srv.Close()
			host := strings.TrimPrefix(srv.URL, "http://")
			res := Prober{Scheme: "http"}.Run(context.Background(), host)
			if res.Failed != tc.failed {
				t.Fatalf("failed stage = %q, want %q (%+v)", res.Failed, tc.failed, res.Stages)
			}
			if res.OK != (tc.failed == "") {
				t.Fatalf("ok = %v for %q", res.OK, tc.name)
			}
			if tc.failed != "" {
				last := res.Stages[len(res.Stages)-1]
				if last.Name != tc.failed || last.OK {
					t.Fatalf("last stage = %+v, want failed %q", last, tc.failed)
				}
			}
		})
	}
}

func TestRunFailsAtConnectWhenNothingListens(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	host := strings.TrimPrefix(srv.URL, "http://")
	srv.Close()
	res := Prober{Scheme: "http"}.Run(context.Background(), host)
	if res.OK || res.Failed != "connect" {
		t.Fatalf("result = %+v, want connect failure", res)
	}
}

func TestRunRejectsAnEmptyHost(t *testing.T) {
	res := Prober{}.Run(context.Background(), "  ")
	if res.Failed != "config" {
		t.Fatalf("failed stage = %q, want config", res.Failed)
	}
}
