package store

import (
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// A tenant's save lands on the tenant's own site even when the body names
// another one, and the default site is left untouched.
func TestScanScheduleUsesStoreSite(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	site, err := st.CreateSite("bravo", "Bravo", "console.bravo.test")
	if err != nil {
		t.Fatal(err)
	}
	bravo := st.InSite(site.ID)
	if err := bravo.SaveScanSchedule(model.ScanSchedule{
		SiteID: st.SiteID(), Cadence: "daily", Hour: 2, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if sched, err := bravo.ScanSchedule(site.ID); err != nil || sched == nil {
		t.Fatalf("the tenant's own schedule = %+v, %v", sched, err)
	}
	if sched, err := st.ScanSchedule(st.SiteID()); err != nil || sched != nil {
		t.Fatalf("the default site gained a schedule: %+v, %v", sched, err)
	}
}

// The schedule survives a save intact, and a page save does not clear the
// signature the last run recorded.
func TestScanScheduleRoundTrip(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if sched, err := st.ScanSchedule(st.SiteID()); err != nil || sched != nil {
		t.Fatalf("a site with no schedule = %+v, %v; want nil", sched, err)
	}
	in := model.ScanSchedule{
		SiteID: st.SiteID(), Cadence: "weekly", Hour: 4, Day: 3, Enabled: true,
		Triggers: []string{"config", "kev"}, UpdatedBy: "operator",
	}
	if err := st.SaveScanSchedule(in); err != nil {
		t.Fatal(err)
	}
	if err := st.SetScanSignature(in.SiteID, "sig-1"); err != nil {
		t.Fatal(err)
	}
	// Saving again from the page must not wipe what the last run recorded.
	in.Hour = 5
	if err := st.SaveScanSchedule(in); err != nil {
		t.Fatal(err)
	}

	got, err := st.ScanSchedule(in.SiteID)
	if err != nil || got == nil {
		t.Fatalf("schedule = %+v, %v", got, err)
	}
	if got.Cadence != "weekly" || got.Hour != 5 || got.Day != 3 || !got.Enabled {
		t.Fatalf("schedule = %+v, want the saved cadence", got)
	}
	if len(got.Triggers) != 2 || got.Triggers[0] != "config" || got.Triggers[1] != "kev" {
		t.Fatalf("triggers = %v", got.Triggers)
	}
	if got.Signature != "sig-1" {
		t.Fatalf("signature = %q, want the last run's record", got.Signature)
	}
	if list, err := st.ListScanSchedules(); err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v; want the one saved schedule", list, err)
	}
}
