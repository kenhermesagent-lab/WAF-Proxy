package store

import (
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// Purging the evidence of an old run must leave the run itself: the record
// that a scan happened is not the evidence it produced.
func TestScanEvidencePurgeKeepsRun(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	old := time.Now().Add(-48 * time.Hour)
	id, err := st.CreateScanRun(&model.ScanRun{Target: "app.example.com", Trigger: "schedule", StartedAt: old})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.FinishScanRun(id, old, `{"reached-backend":1}`, "local", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.AddScanEvidence([]model.ScanEvidence{
		{RunID: id, Seq: 0, Stage: "waf", Class: "sqli", Verdict: "reached-backend", WANStatus: 200, UpStatus: 200},
	}); err != nil {
		t.Fatal(err)
	}

	purged, err := st.PurgeScanEvidence(time.Now().Add(-24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if purged != 1 {
		t.Fatalf("purged %d rows, want 1", purged)
	}
	rows, err := st.ListScanEvidence(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("%d evidence rows survived the purge", len(rows))
	}

	runs, err := st.ListScanRuns(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].ID != id {
		t.Fatalf("the run row was purged with its evidence: %+v", runs)
	}
	if runs[0].Verdicts != `{"reached-backend":1}` {
		t.Fatalf("verdicts = %q", runs[0].Verdicts)
	}
}
