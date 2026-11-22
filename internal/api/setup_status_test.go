package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The setup wizard's status endpoint is unauthenticated. Once an administrator
// exists it must not describe the host or the listeners any more.
func TestSetupStatusStopsLeakingAfterSetup(t *testing.T) {
	srv, st, _, _ := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "internal.example.com"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/setup/status", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/setup/status = %d: %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["needs_setup"] != false {
		t.Fatalf("needs_setup = %v, want false", got["needs_setup"])
	}
	if _, ok := got["version"]; !ok {
		t.Error("the version is still needed by the signed-out console")
	}
	for _, leaked := range []string{"base_domain", "wan_ip", "wan_port", "lan_ip", "gui_port", "wan_iface", "lan_iface", "kernel", "geoip"} {
		if _, ok := got[leaked]; ok {
			t.Errorf("%q is still exposed after setup", leaked)
		}
	}
}
