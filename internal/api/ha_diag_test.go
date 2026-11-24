package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func TestHADiagnosticsReportsOutbox(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.SetNodeID("node-a")
	if _, err := st.AddBan(&model.Ban{CIDR: "203.0.113.9", Reason: "test", Source: "manual"}); err != nil {
		t.Fatal(err)
	}
	srv := &Server{st: st}
	srv.SetHAStatus(func() HAStatus {
		return HAStatus{Enabled: true, Role: "active", State: "active", Serving: true, PeerFingerprint: "peer"}
	})

	rec := httptest.NewRecorder()
	srv.haDiagnostics(rec, httptest.NewRequest(http.MethodGet, "/api/ha/diagnostics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("diagnostics status = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Enabled bool   `json:"enabled"`
		Role    string `json:"role"`
		Outbox  struct {
			Depth   int64            `json:"depth"`
			Pending map[string]int64 `json:"pending_by_kind"`
		} `json:"outbox"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Enabled || body.Role != "active" {
		t.Fatalf("diagnostics role = %+v", body)
	}
	if body.Outbox.Depth != 1 || body.Outbox.Pending["bans"] != 1 {
		t.Fatalf("diagnostics outbox = %+v", body.Outbox)
	}
}
