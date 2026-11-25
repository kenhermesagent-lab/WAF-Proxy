package scan

// The scan catalogue is only meaningful if each attack payload actually trips a
// signature. A payload that stopped matching after a CRS bump would make every
// run report "reached-backend" for a class nothing tests, so the catalogue is
// pinned against the shipped engine here, one probe at a time, together with
// the benign control that proves the block was not a blanket refusal.

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

// catalogueEngine compiles the engine a site without a profile falls back to,
// which is what every payload has to survive.
func catalogueEngine(t *testing.T) *waf.Engine {
	t.Helper()
	id := int64(1)
	set := waf.NewSet([]model.Profile{{
		ID: id, Name: "catalogue", Mode: "block", Paranoia: 1, Anomaly: 5, MaxBody: 131072,
	}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	engine := set.For(&id)
	if engine == nil {
		t.Fatal("no engine compiled")
	}
	return engine
}

// catalogueRequest builds the request the runner would send for a probe, so the
// test pins the wire shape the catalogue really produces.
func catalogueRequest(p Probe) *http.Request {
	target := p.Path
	if p.Query != "" {
		target += "?" + p.Query
	}
	req := httptest.NewRequest(p.Method, target, strings.NewReader(p.Body))
	for name, values := range p.Header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", scanUserAgent)
	}
	if p.Body != "" {
		req.ContentLength = int64(len(p.Body))
		req.Header.Set("Content-Length", strconv.Itoa(len(p.Body)))
	}
	return req
}

// TestCataloguePayloadsFireARule is the catalogue's contract with the engine:
// every WAF-stage payload is refused, and its own control is not. A payload
// that stops firing fails here before a scan can report a false "reached".
func TestCataloguePayloadsFireARule(t *testing.T) {
	engine := catalogueEngine(t)
	probePath, err := NewProbePath()
	if err != nil {
		t.Fatal(err)
	}
	client := netip.MustParseAddr("203.0.113.9")

	for _, class := range wafClasses(probePath) {
		control := engine.Inspect(catalogueRequest(class.Control), []byte(class.Control.Body), client)
		if control.Blocked {
			t.Fatalf("%s: the control was refused by rule %d (%s); a blanket refusal cannot be told apart from a rule",
				class.Control.Class, control.RuleID, control.Message)
		}
		if len(class.Probes) == 0 {
			t.Fatalf("%s: class carries no payload", class.Control.Class)
		}
		for _, p := range class.Probes {
			res := engine.Inspect(catalogueRequest(p), []byte(p.Body), client)
			if !res.Blocked {
				t.Errorf("%s (%s %s?%s): not blocked by the WAF", p.Class, p.Method, p.Path, p.Query)
			}
		}
	}
}
