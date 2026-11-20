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

	// Blank fields: the names the collector samples are reported, and both are
	// marked as auto-detected (an empty name is still reported when the host has
	// no other interface).
	blank := get()
	wan, lan := srv.metrics.Detected()
	if got, ok := blank["wan_iface_in_use"]; !ok || got != wan {
		t.Errorf("wan_iface_in_use = %q (reported %v), want %q", got, ok, wan)
	}
	if got, ok := blank["lan_iface_in_use"]; !ok || got != lan {
		t.Errorf("lan_iface_in_use = %q (reported %v), want %q", got, ok, lan)
	}
	if blank["wan_iface_auto"] != "1" || blank["lan_iface_auto"] != "1" {
		t.Errorf("blank interface fields were not marked auto-detected: %v", blank)
	}
	if _, ok := blank["iface_available"]; !ok {
		t.Errorf("settings did not list available interfaces: %v", blank)
	}

	// A configured field keeps reporting what is sampled but is no longer
	// labelled as auto-detected, while the blank field still is.
	if err := st.SetSettings(map[string]string{"wan_iface": "eth9"}); err != nil {
		t.Fatal(err)
	}
	set := get()
	if _, ok := set["wan_iface_in_use"]; !ok {
		t.Errorf("configured wan_iface stopped reporting the sampled interface: %v", set)
	}
	if _, ok := set["wan_iface_auto"]; ok {
		t.Errorf("configured wan_iface was still marked auto-detected: %v", set)
	}
	if set["lan_iface_auto"] != "1" {
		t.Errorf("blank lan_iface was not marked auto-detected: %v", set)
	}
}
