package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/canary"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/canary/canarytest"
)

func TestHealthReportsCanarySnapshot(t *testing.T) {
	srv, st, _, _ := newObservabilityServer(t)
	if err := st.SetSetting("canary_host", "app.example.com"); err != nil {
		t.Fatal(err)
	}
	m := canary.NewMonitor(st, &canarytest.Probe{Result: canary.Result{OK: true,
		Stages: []canary.Stage{{Name: "connect", OK: true, Detail: "8ms"}}}}, nil)
	m.Check(context.Background())
	srv.SetCanary(m)

	rec := httptest.NewRecorder()
	srv.health(rec, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("health = %d", rec.Code)
	}
	var body struct {
		Canary canary.Snapshot `json:"canary"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Canary.Host != "app.example.com" || !body.Canary.OK || body.Canary.LatencyMS != 8 {
		t.Fatalf("canary in health = %+v", body.Canary)
	}
}
