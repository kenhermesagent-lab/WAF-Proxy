package scan

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func dailySchedule() model.ScanSchedule {
	return model.ScanSchedule{SiteID: 1, Cadence: CadenceDaily, Hour: 3, Enabled: true}
}

// A follower decides nothing and starts nothing: two nodes must never scan the
// same published path at once.
func TestSchedulerRunsOnLeaderOnly(t *testing.T) {
	now := time.Date(2026, 5, 20, 4, 0, 0, 0, time.UTC)
	var runs, skips []string
	sched := &Scheduler{
		Leader:     false,
		Now:        func() time.Time { return now },
		Signature:  func(int64) (string, error) { return "sig-1", nil },
		Run:        func(_ context.Context, _ int64, trigger, _ string) error { runs = append(runs, trigger); return nil },
		RecordSkip: func(_ int64, reason string) error { skips = append(skips, reason); return nil },
	}
	inputs := []Input{{Schedule: dailySchedule()}}

	results, err := sched.Tick(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 0 {
		t.Fatalf("a follower started %d scan(s)", len(runs))
	}
	if len(skips) != 1 || !strings.Contains(skips[0], "leader") {
		t.Fatalf("skips = %v, want one leader refusal", skips)
	}
	if results[0].Ran {
		t.Fatal("a follower reported that it ran a scan")
	}

	sched.Leader = true
	if _, err := sched.Tick(context.Background(), inputs); err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0] != TriggerSchedule {
		t.Fatalf("runs = %v, want one scheduled run", runs)
	}
}

// A due site whose configuration, fingerprint and version are unchanged is
// recorded as skipped, not scanned again. A new KEV entry still triggers it.
func TestScheduleSkipsWhenConfigUnchanged(t *testing.T) {
	now := time.Date(2026, 5, 20, 4, 0, 0, 0, time.UTC)
	runs := 0
	var skips []string
	sched := &Scheduler{
		Leader:     true,
		Now:        func() time.Time { return now },
		Signature:  func(int64) (string, error) { return "sig-1", nil },
		Run:        func(context.Context, int64, string, string) error { runs++; return nil },
		RecordSkip: func(_ int64, reason string) error { skips = append(skips, reason); return nil },
	}
	inputs := []Input{{Schedule: dailySchedule(), Signature: "sig-1"}}

	results, err := sched.Tick(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if runs != 0 {
		t.Fatalf("an unchanged site was scanned %d time(s)", runs)
	}
	if results[0].Ran || !strings.Contains(results[0].Reason, "nothing changed") {
		t.Fatalf("result = %+v, want a skip for an unchanged site", results[0])
	}

	// The feed changed, which is exactly when patching is urgent, so the run
	// happens even though the configuration did not move.
	if _, err := sched.TriggerNow(context.Background(), inputs[0], TriggerKEV); err != nil {
		t.Fatal(err)
	}
	if runs != 1 {
		t.Fatalf("a matching new KEV entry caused %d runs, want 1", runs)
	}
}

// Only entries that appeared since the previous snapshot, and only those naming
// a component the site runs, are worth an unscheduled run.
func TestNewKEVTriggersRunForMatchingComponent(t *testing.T) {
	prev := &KEV{Entries: map[string]KEVEntry{
		"CVE-2024-0001": {CVEID: "CVE-2024-0001", Product: "Jenkins"},
	}}
	next := &KEV{Entries: map[string]KEVEntry{
		"CVE-2024-0001": {CVEID: "CVE-2024-0001", Product: "Jenkins"},
		"CVE-2024-0002": {CVEID: "CVE-2024-0002", Product: "Grafana"},
		"CVE-2024-0003": {CVEID: "CVE-2024-0003", Product: "PostgreSQL"},
	}}

	added := NewKEVEntries(prev, next)
	if len(added) != 2 {
		t.Fatalf("new entries = %+v, want the two that appeared", added)
	}
	watched := []Component{{Product: "grafana", Label: "Grafana", Version: "10.2.0"}}
	matched := KEVMatchesWatched(added, watched)
	if len(matched) != 1 || matched[0].CVEID != "CVE-2024-0002" {
		t.Fatalf("matches = %+v, want only the Grafana entry", matched)
	}
}

// The cadence window is stable per site and the last run inside it suppresses a
// second run of the same window.
func TestScheduleDueWindows(t *testing.T) {
	sched := model.ScanSchedule{SiteID: 4, Cadence: CadenceWeekly, Hour: 3, Day: 3, Enabled: true}
	// Wednesday 2026-05-20, 04:00 UTC.
	now := time.Date(2026, 5, 20, 4, 0, 0, 0, time.UTC)
	if !Due(sched, now, nil) {
		t.Fatal("a weekly schedule is not due on its own morning")
	}
	anHourAgo := now.Add(-time.Hour)
	if Due(sched, now, &anHourAgo) {
		t.Fatal("a site that already ran this window is due again")
	}
	eightDaysAgo := now.AddDate(0, 0, -8)
	if !Due(sched, now, &eightDaysAgo) {
		t.Fatal("a site that has not run this window is not due")
	}
}
