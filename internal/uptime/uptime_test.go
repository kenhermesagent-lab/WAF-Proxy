package uptime

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

type fakeNotifier struct {
	kinds  []string
	dedupe []string
}

func (f *fakeNotifier) Enqueue(kind, _, dedupe string, _ bool) {
	f.kinds = append(f.kinds, kind)
	f.dedupe = append(f.dedupe, dedupe)
}

func TestMonitorReportsUpDownAndRecovery(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	proxyID, err := st.CreateProxy(&model.Proxy{Hostname: "app.example.com", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()
	if err := st.ReplaceUpstreams(proxyID, []model.Upstream{{URL: backend.URL, Enabled: true}}); err != nil {
		t.Fatal(err)
	}

	notes := &fakeNotifier{}
	m := New(st, notes, slog.New(slog.NewTextHandler(io.Discard, nil)))
	first := m.Check(context.Background())
	if len(first.Targets) != 1 || first.Targets[0].State != StateUp {
		t.Fatalf("first check = %+v, want one up target", first.Targets)
	}
	if first.Proxies[0].State != StateUp || first.Proxies[0].Up != 1 {
		t.Fatalf("proxy status = %+v", first.Proxies[0])
	}

	backend.Close()
	second := m.Check(context.Background())
	if len(second.Targets) != 1 || second.Targets[0].State != StateDown {
		t.Fatalf("second check = %+v, want down target", second.Targets)
	}
	if len(notes.kinds) != 1 || notes.kinds[0] != "uptime" {
		t.Fatalf("alerts = %+v, want one uptime alert", notes.kinds)
	}
	if second.Targets[0].Checks24 != 2 || second.Targets[0].Uptime24 != 50 {
		t.Fatalf("uptime history = %+v, want 50%% over two checks", second.Targets[0])
	}
}
