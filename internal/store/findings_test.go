package store

import (
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// The scan stages do not fill in a target; the merge must stamp the hostname
// the run scanned, or the page shows a finding that belongs to no site.
func TestMergeScanFindingsStampsTarget(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now()
	opened, resolved, err := st.MergeScanFindings(st.SiteID(), "billing.example.com", []model.ScanFinding{{
		Key: "exposure:/billing.env", Stage: "exposure", Class: "sensitive-file",
		Title: "The application serves /.env", Severity: "medium",
		Recommendation: "Block the path",
	}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(opened) != 1 || len(resolved) != 0 {
		t.Fatalf("opened=%d resolved=%d, want 1/0", len(opened), len(resolved))
	}
	if opened[0].Target != "billing.example.com" {
		t.Fatalf("opened target = %q, want the run's hostname", opened[0].Target)
	}
	stored, err := st.ListScanFindings("", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].Target != "billing.example.com" {
		t.Fatalf("stored findings = %+v, want one with the run's hostname", stored)
	}
}
