package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
)

// TestSettingsInterfaceHints checks that Settings can show what auto-detection
// picked and which interface names exist on the host.
func TestSettingsInterfaceHints(t *testing.T) {
	srv, st, token, _ := newObservabilityServer(t)
	srv.geo = geoip.Open(t.TempDir())
	get := func() map[string]string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
		req.Host = "gui.local"
		req.RemoteAddr = "192.168.101.10:5000"
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/settings = %d: %s", rec.Code, rec.Body.String())
		}
		var out map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// Blank fields: the collector's auto-detected names are reported (an empty
	// name is still reported when the host has no other interface).
	blank := get()
	if _, ok := blank["wan_iface_detected"]; !ok {
		t.Errorf("blank wan_iface did not report a detected name: %v", blank)
	}
	if _, ok := blank["lan_iface_detected"]; !ok {
		t.Errorf("blank lan_iface did not report a detected name: %v", blank)
	}
	if _, ok := blank["iface_available"]; !ok {
		t.Errorf("settings did not list available interfaces: %v", blank)
	}

	// Explicitly configured fields are not labelled as auto-detected.
	if err := st.SetSettings(map[string]string{"wan_iface": "eth9"}); err != nil {
		t.Fatal(err)
	}
	set := get()
	if _, ok := set["wan_iface_detected"]; ok {
		t.Errorf("configured wan_iface was still reported as detected: %v", set)
	}
}
