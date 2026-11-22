package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/anomaly"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
)

type nopNotifier struct{}

func (nopNotifier) Enqueue(string, string, string, bool) {}

func TestAnomalySettingsAndEvents(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	srv.SetAnomaly(anomaly.New(st, metrics.New("", ""), nopNotifier{}, slog.New(slog.NewTextHandler(io.Discard, nil))))

	put := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/api/anomaly/settings", strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		req.Header.Set("X-CSRF-Token", csrf)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	if rec := put(`{"enabled":true,"egress_mb":0,"egress_factor":4,"rate_rps":200,"rate_factor":3,"auth_burst":20}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("an invalid threshold was accepted: %d %s", rec.Code, rec.Body)
	}
	rec := put(`{"enabled":true,"egress_mb":8,"egress_factor":5,"rate_rps":150,"rate_factor":2.5,"auth_burst":25}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("save failed: %d %s", rec.Code, rec.Body)
	}

	get := httptest.NewRequest(http.MethodGet, "/api/anomaly", nil)
	get.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	grec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(grec, get)
	if grec.Code != http.StatusOK {
		t.Fatalf("read failed: %d", grec.Code)
	}
	var out struct {
		Events []any `json:"events"`
		Config struct {
			EgressMB int `json:"egress_mb"`
		} `json:"config"`
	}
	if err := json.Unmarshal(grec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Config.EgressMB != 8 || len(out.Events) != 0 {
		t.Fatalf("unexpected read: %s", grec.Body)
	}
}
