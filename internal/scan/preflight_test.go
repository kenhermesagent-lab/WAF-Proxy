package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func targetFor(t *testing.T, wan, up *httptest.Server) Target {
	t.Helper()
	return Target{
		Proxy:    model.Proxy{Hostname: "app.example.com", Enabled: true, GateMode: "off"},
		WAN:      endpoint(t, wan, "app.example.com"),
		Upstream: endpoint(t, up, "app.example.com"),
	}
}

// A path that answers 200 is a catch-all or an SPA router: a body sent there
// would reach an application route, so the body classes must not be sent.
func TestProbePathCatchAllSkipsBodyProbes(t *testing.T) {
	up := newUpstream(t)
	wan := newWAN(t, up, nil)
	r := NewRunner(endpoint(t, wan, "app.example.com"), endpoint(t, up.srv, "app.example.com"), 0)

	pf, err := r.RunPreflight(context.Background(), targetFor(t, wan, up.srv))
	if err != nil {
		t.Fatal(err)
	}
	if pf.BodyProbes {
		t.Fatalf("a catch-all route was accepted as a 404: %+v", pf.Checks)
	}
	var sawCheck bool
	for _, c := range pf.Checks {
		if c.Name == "probe path" {
			sawCheck = true
			if c.OK {
				t.Fatalf("the probe-path check passed against a catch-all: %s", c.Detail)
			}
		}
	}
	if !sawCheck {
		t.Fatal("preflight did not report the probe-path check")
	}

	probes := Catalogue(pf)
	var body int
	for _, p := range probes {
		if p.Method == http.MethodPost {
			body++
			if p.Skip != skipCatchAll {
				t.Errorf("%s: skip = %q, want the catch-all note", p.Class, p.Skip)
			}
		}
	}
	if body == 0 {
		t.Fatal("the catalogue has no body probes, so this test proves nothing")
	}

	rows, err := r.Run(context.Background(), probes)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Method == http.MethodPost && (row.Verdict != string(NotRun) || row.Note != skipCatchAll) {
			t.Errorf("%s: %q (%s), want not-run with the catch-all note", row.Class, row.Verdict, row.Note)
		}
	}
	methods, _ := up.seen()
	for _, method := range methods {
		if method == http.MethodPost {
			t.Fatal("a body probe reached the application")
		}
	}
}

// The framing and wire-shape probes are sent raw, on their own connection, and
// never replayed: the fake upstream must not see one.
func TestFramingProbesAreWanOnly(t *testing.T) {
	up := newUpstream(t)
	wan := newWAN(t, up, func(r *http.Request) bool {
		return strings.HasPrefix(r.URL.Path, ProbePathPrefix)
	})
	r := NewRunner(endpoint(t, wan, "app.example.com"), endpoint(t, up.srv, "app.example.com"), 0)

	pf := &Preflight{Host: "app.example.com", ProbePath: ProbePathPrefix + "test", Path: PathLocal, BodyProbes: true}
	var raw []Probe
	for _, p := range Catalogue(pf) {
		if p.WANOnly {
			raw = append(raw, p)
		}
	}
	if len(raw) < 4 {
		t.Fatalf("the catalogue has %d raw probes, want the four wire shapes", len(raw))
	}

	rows, err := r.Run(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.UpStatus != 0 || row.UpHash != "" {
			t.Errorf("%s was replayed at the upstream: status=%d hash=%q", row.Class, row.UpStatus, row.UpHash)
		}
		if row.Verdict != string(BlockedWAF) && row.Verdict != string(NotBlocked) {
			t.Errorf("%s = %q (%s), want a verdict from the published answer alone", row.Class, row.Verdict, row.Note)
		}
		if !strings.Contains(row.Note, "upstream half was skipped") {
			t.Errorf("%s: note = %q, want the skipped half named", row.Class, row.Note)
		}
	}
	methods, paths := up.seen()
	for _, method := range methods {
		if method == http.MethodPost {
			t.Fatalf("a framing probe reached the upstream as a POST")
		}
	}
	for _, path := range paths {
		if strings.Contains(path, ".wafscan") {
			t.Fatalf("a raw probe reached the upstream: %s", path)
		}
	}
}

// CF-Ray is what separates "tested the operator's edge" from "tested this
// node's own WAF", and the run has to record which one happened.
func TestLocalPathRecordedWhenNoCFRay(t *testing.T) {
	up := newUpstream(t)
	local := newWAN(t, up, nil)
	r := NewRunner(endpoint(t, local, "app.example.com"), endpoint(t, up.srv, "app.example.com"), 0)
	pf, err := r.RunPreflight(context.Background(), targetFor(t, local, up.srv))
	if err != nil {
		t.Fatal(err)
	}
	if pf.Path != PathLocal {
		t.Fatalf("path = %q, want %q when no CF-Ray is present", pf.Path, PathLocal)
	}

	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-Ray", "8a1b2c3d4e5f6a7b-AMS")
		_, _ = w.Write([]byte("hello from the app"))
	}))
	defer edge.Close()
	r = NewRunner(endpoint(t, edge, "app.example.com"), endpoint(t, up.srv, "app.example.com"), 0)
	pf, err = r.RunPreflight(context.Background(), targetFor(t, edge, up.srv))
	if err != nil {
		t.Fatal(err)
	}
	if pf.Path != PathEdge {
		t.Fatalf("path = %q, want %q when the answer carries CF-Ray", pf.Path, PathEdge)
	}
}

// A disabled site has nothing to test, and preflight says so rather than
// sending traffic at a hostname that is not serving.
func TestPreflightSkipsADisabledSite(t *testing.T) {
	up := newUpstream(t)
	wan := newWAN(t, up, nil)
	r := NewRunner(endpoint(t, wan, "app.example.com"), endpoint(t, up.srv, "app.example.com"), 0)

	target := targetFor(t, wan, up.srv)
	target.Proxy.Enabled = false
	pf, err := r.RunPreflight(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if pf.Skip == "" {
		t.Fatal("a disabled site was not skipped")
	}
	for _, p := range Catalogue(pf) {
		if p.Skip == "" {
			t.Fatalf("%s %s would have been sent to a disabled site", p.Class, p.Method)
		}
	}
	if methods, _ := up.seen(); len(methods) != 0 {
		t.Fatalf("preflight sent %d request(s) to a disabled site", len(methods))
	}
}
