package scan

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// upstream records every method it is asked for, so a test can prove the
// scanner never wrote to the application.
type upstream struct {
	srv     *httptest.Server
	mu      sync.Mutex
	methods []string
	paths   []string
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.methods = append(u.methods, r.Method)
		u.paths = append(u.paths, r.URL.RequestURI())
		u.mu.Unlock()
		if strings.Contains(r.URL.RawQuery, "attack") {
			_, _ = w.Write([]byte("the application answered"))
			return
		}
		_, _ = w.Write([]byte("hello from the app"))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) seen() ([]string, []string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.methods...), append([]string(nil), u.paths...)
}

// newWAN serves the published path: it blocks what block() matches and
// forwards the rest, the way a WAF in front of the proxy would.
func newWAN(t *testing.T, up *upstream, block func(*http.Request) bool) *httptest.Server {
	t.Helper()
	client := &http.Client{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if block != nil && block(r) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("request blocked by the edge"))
			return
		}
		req, err := http.NewRequestWithContext(r.Context(), r.Method, up.srv.URL+r.URL.RequestURI(), r.Body)
		if err != nil {
			http.Error(w, "bad probe", http.StatusBadRequest)
			return
		}
		req.Host = r.Host
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "upstream down", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func endpoint(t *testing.T, srv *httptest.Server, host string) Endpoint {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return Endpoint{URL: u, Host: host}
}

func TestScanNeverMutatesUpstream(t *testing.T) {
	up := newUpstream(t)
	wan := newWAN(t, up, nil)
	r := NewRunner(endpoint(t, wan, "app.example.com"), endpoint(t, up.srv, "app.example.com"), 0)

	probes := []Probe{
		{Stage: "edge", Class: "method", Method: http.MethodGet, Path: "/"},
		{Stage: "edge", Class: "method", Method: http.MethodHead, Path: "/"},
		{Stage: "edge", Class: "method", Method: http.MethodOptions, Path: "/"},
		{Stage: "edge", Class: "method", Method: http.MethodDelete, Path: "/"},
		{Stage: "edge", Class: "method", Method: http.MethodPut, Path: "/api/upload"},
		{Stage: "edge", Class: "method", Method: http.MethodPost, Path: "/api/upload"},
	}
	rows, err := r.Run(context.Background(), probes)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows[3:] {
		if row.Verdict != string(NotRun) {
			t.Errorf("%s %s = %q, want not-run", row.Method, row.Path, row.Verdict)
		}
	}
	methods, paths := up.seen()
	for _, method := range methods {
		switch method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			t.Fatalf("the upstream saw a %s request", method)
		}
	}
	for _, path := range paths {
		if strings.Contains(path, "/api/upload") {
			t.Fatalf("a refused probe reached the upstream: %s", path)
		}
	}
}

func TestRunnerStopsOnSustained429(t *testing.T) {
	up := newUpstream(t)
	wan := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("slow down"))
	}))
	defer wan.Close()
	r := NewRunner(endpoint(t, wan, "app.example.com"), endpoint(t, up.srv, "app.example.com"), 0)

	probes := make([]Probe, 10)
	for i := range probes {
		probes[i] = Probe{Stage: "waf", Class: "sqli", Method: http.MethodGet, Path: "/"}
	}
	rows, err := r.Run(context.Background(), probes)
	if !errors.Is(err, ErrAborted) {
		t.Fatalf("err = %v, want ErrAborted", err)
	}
	if len(rows) != maxRefusals {
		t.Fatalf("stored %d rows, want %d before the abort", len(rows), maxRefusals)
	}
	if rows[0].Verdict != string(BlockedWAF) {
		t.Fatalf("verdict = %q, want blocked-waf", rows[0].Verdict)
	}
}

// A refused control means the class proves nothing: the refusal could be a
// blanket rule. The rest of the class is not sent, because more requests into a
// refusal only deepen a rate limit.
func TestControlRefusalSkipsClass(t *testing.T) {
	up := newUpstream(t)
	wan := newWAN(t, up, func(*http.Request) bool { return true })
	r := NewRunner(endpoint(t, wan, "app.example.com"), endpoint(t, up.srv, "app.example.com"), 0)

	rows, err := r.Run(context.Background(), []Probe{
		{Stage: "waf", Class: "sqli", Method: http.MethodGet, Path: "/.wafscan/test", Query: "id=1", Control: true},
		{Stage: "waf", Class: "sqli", Method: http.MethodGet, Path: "/.wafscan/test", Query: "id=attack"},
		{Stage: "waf", Class: "sqli", Method: http.MethodGet, Path: "/.wafscan/test", Query: "id=more"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].Verdict != string(Inconclusive) || rows[0].Note != "the control request was refused too" {
		t.Fatalf("control = %q (%s), want inconclusive with the refusal named", rows[0].Verdict, rows[0].Note)
	}
	for _, row := range rows[1:] {
		if row.Verdict != string(NotRun) || row.Note != skipControl {
			t.Fatalf("%s = %q (%s), want not-run because the control was refused", row.Detail, row.Verdict, row.Note)
		}
	}
	// The control itself is compared on both sides; the payloads are not sent
	// anywhere once it is refused.
	methods, paths := up.seen()
	if len(methods) != 1 {
		t.Fatalf("the upstream saw %d request(s), want only the control", len(methods))
	}
	for _, path := range paths {
		if !strings.Contains(path, "id=1") {
			t.Fatalf("a payload reached the upstream after its control was refused: %s", path)
		}
	}
}
