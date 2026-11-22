package policy

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/norm"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

func TestNormalizationModeSettingFallsBackToFlag(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "flag"}, {"off", "off"}, {"flag", "flag"}, {"block", "block"}, {"sometimes", "flag"},
	} {
		if got := normalizationMode(tc.in); got != tc.want {
			t.Errorf("normalizationMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormVerdictFollowsTheMode(t *testing.T) {
	pol, _, _ := newEngine(t)
	dup := []norm.Finding{{Kind: "duplicate-parameter", Source: "query", Parameter: "id"}}

	pol.settings.NormalizationMode = "off"
	if _, ok := pol.normVerdict(dup); ok {
		t.Fatal("off mode produced a verdict")
	}

	pol.settings.NormalizationMode = "flag"
	v, ok := pol.normVerdict(dup)
	if !ok || v.Action != "log" || v.Rule != "900120" || v.Status != http.StatusOK {
		t.Fatalf("flag mode = %+v ok=%v", v, ok)
	}

	pol.settings.NormalizationMode = "block"
	if v, _ = pol.normVerdict(dup); v.Action != "block" || v.Status != http.StatusForbidden {
		t.Fatalf("block mode = %+v", v)
	}

	if v, _ = pol.normVerdict([]norm.Finding{{Kind: "double-encoded", Source: "body", Parameter: "next", First: "%3Cb%3E", Second: "<b>"}}); v.Rule != "900121" {
		t.Fatalf("double encoding reported rule %q", v.Rule)
	}
}

// A proxy in block mode refuses a request the rule set let through when the
// normalization check finds a repeated parameter with two different values.
func TestNormalizationBlockReachesThePipeline(t *testing.T) {
	pol, st, _ := newEngine(t)
	if err := st.SetSetting("normalization_mode", "block"); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}
	id := int64(7)
	pol.wafs = waf.NewSet([]model.Profile{{ID: id, Name: "norm", Mode: "block", Paranoia: 1, Anomaly: 5, MaxBody: 131072}}, pol.log)
	proxy := &model.Proxy{Hostname: "app.example.com", Enabled: true, WAFMode: "block", ProfileID: &id}
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/search?colour=red&colour=blue", nil)

	verdict, info := pol.Inspect(&Request{
		Proxy: proxy, Addr: netip.MustParseAddr("203.0.113.9"), Method: http.MethodGet, HTTP: req,
	})
	if verdict.Action != "block" || verdict.Status != http.StatusForbidden {
		t.Fatalf("verdict = %+v info = %+v", verdict, info)
	}
	if verdict.Rule != "900120" {
		t.Fatalf("blocked by rule %q, want the normalization rule 900120", verdict.Rule)
	}
}
