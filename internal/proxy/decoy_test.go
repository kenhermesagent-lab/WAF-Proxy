package proxy

import (
	"net/http"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// End-to-end regression for the decoy honeypot: a whitelisted client asking for
// a decoy path with dot-segment or duplicate-slash obfuscation must still be
// banned instead of reaching the upstream.
func TestPipelineDecoyPathCannotBeObfuscated(t *testing.T) {
	for _, path := range []string{"/.env", "/./.env", "//.env", "/x/../.env"} {
		t.Run(path, func(t *testing.T) {
			h := newHarness(t)
			if _, err := h.st.CreatePolicy(&model.Policy{
				Scope: "global", Kind: model.PolicyIPWhitelist, Value: testIP + "/32", Action: "allow", Enabled: true,
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := h.st.CreatePolicy(&model.Policy{
				Scope: "global", Kind: model.PolicyDecoy, Value: "/.env", Action: "block", Enabled: true,
			}); err != nil {
				t.Fatal(err)
			}
			if err := h.pol.Reload(); err != nil {
				t.Fatal(err)
			}
			rec := h.request(http.MethodGet, testHost, path, "", nil)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s status = %d, want 403", path, rec.Code)
			}
			h.waitEvent(t, func(e model.Event) bool { return e.Stage == "decoy" && e.Action == "ban" })
			if h.hits.Load() != 0 {
				t.Fatalf("%s reached the upstream", path)
			}
		})
	}
}
