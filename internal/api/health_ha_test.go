package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthReportsHAAndReadiness(t *testing.T) {
	srv := &Server{started: time.Now()}
	status := HAStatus{Enabled: true, Role: "standby", State: "ready-standby", Serving: false}
	srv.SetHAStatus(func() HAStatus { return status })

	call := func() (int, map[string]any) {
		rec := httptest.NewRecorder()
		srv.health(rec, httptest.NewRequest(http.MethodGet, "/api/health?ready=1", nil))
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("health body: %v", err)
		}
		return rec.Code, body
	}

	code, body := call()
	if code != http.StatusServiceUnavailable {
		t.Fatalf("standby ready=1 status = %d, want 503", code)
	}
	ha, ok := body["ha"].(map[string]any)
	if !ok || ha["role"] != "standby" {
		t.Fatalf("health ha block = %v", body["ha"])
	}

	status = HAStatus{Enabled: true, Role: "active", State: "active", Serving: true}
	code, body = call()
	if code != http.StatusOK || body["ready"] != true {
		t.Fatalf("active health = %d %v, want 200 ready", code, body)
	}

	// HA off must not affect readiness on a single node.
	status = HAStatus{Enabled: false, Role: "standalone", State: "standalone", Serving: true}
	if code, _ := call(); code != http.StatusOK {
		t.Fatalf("HA off ready=1 status = %d, want 200", code)
	}
}
