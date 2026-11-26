package store

import (
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// The operator's acceptance reason lives in its own column: a later run
// rewrites the scan note, and a reopen changes the state, but neither may
// overwrite the reason.
func TestAcceptedReasonSurvivesReopen(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	finding := model.ScanFinding{
		Key: "exposure:/.env", Stage: "backend", Class: "exposure",
		Title: "The application serves /.env", Severity: "high",
		Recommendation: "Remove the file", Note: "served HTTP 200",
	}
	if _, _, err := st.MergeScanFindings(st.SiteID(), "app.example.com", []model.ScanFinding{finding}, time.Now()); err != nil {
		t.Fatal(err)
	}
	reason := "risk accepted until the Q3 migration"
	if err := st.UpdateScanFinding(finding.Key, "accepted", &reason); err != nil {
		t.Fatal(err)
	}

	// The next run proves it again and rewrites the scan note.
	finding.Note = "served HTTP 200, 19 bytes"
	if _, _, err := st.MergeScanFindings(st.SiteID(), "app.example.com", []model.ScanFinding{finding}, time.Now()); err != nil {
		t.Fatal(err)
	}
	stored := listOne(t, st)
	if stored.State != "accepted" || stored.Reason != reason {
		t.Fatalf("after a run: state=%q reason=%q, want accepted with the reason kept", stored.State, stored.Reason)
	}
	if stored.Note != finding.Note {
		t.Fatalf("scan note = %q, want %q", stored.Note, finding.Note)
	}

	// Reopening keeps the reason and leaves the scan note alone.
	if err := st.UpdateScanFinding(finding.Key, "open", nil); err != nil {
		t.Fatal(err)
	}
	stored = listOne(t, st)
	if stored.State != "open" {
		t.Fatalf("state = %q, want open", stored.State)
	}
	if stored.Reason != reason {
		t.Fatalf("reason after reopen = %q, want it kept", stored.Reason)
	}
	if stored.Note != finding.Note {
		t.Fatalf("note after reopen = %q, want the scan note untouched", stored.Note)
	}
}

func listOne(t *testing.T, st *Store) model.ScanFinding {
	t.Helper()
	list, err := st.ListScanFindings("", "")
	if err != nil || len(list) != 1 {
		t.Fatalf("findings = %+v, %v", list, err)
	}
	return list[0]
}

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
