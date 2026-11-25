package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// The shared run path records the run, its evidence and its verdict counts, and
// the endpoints it uses come from the proxy record, not the request.
func TestExecuteRecordsARun(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	id, err := st.CreateProxy(&model.Proxy{Hostname: "app.example.com", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceUpstreams(id, []model.Upstream{
		{ProxyID: id, URL: upstream.URL, Weight: 1, Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}
	proxy, err := st.GetProxy(id)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	run, err := Execute(ctx, ExecuteDeps{
		Store:   st,
		OSV:     fakeAdvisories{},
		WANBase: func(string) string { return upstream.URL },
	}, *proxy, TriggerManual, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if run.ID == 0 || run.EndedAt == nil {
		t.Fatalf("run = %+v, want a finished run", run)
	}
	if run.Path != PathLocal {
		t.Fatalf("path = %q, want local for a listener without CF-Ray", run.Path)
	}
	if run.Verdicts == "" {
		t.Fatal("the run recorded no verdict counts")
	}
	evidence, err := st.ListScanEvidence(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) < 10 {
		t.Fatalf("evidence rows = %d, want the catalogue, gate and backend stages", len(evidence))
	}
	for i, row := range evidence {
		if row.Seq != i {
			t.Fatalf("evidence seq %d = %d, want a unique sequence", i, row.Seq)
		}
	}
}
