package store

import (
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func TestUtilizationRollupKeepsHourlyMeansAndCounts(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	testProxy(t, st, "app.example.com")

	hour := time.Now().UTC().Truncate(time.Hour)
	if err := st.InsertEvents([]model.Event{
		{TS: hour.Add(time.Minute), ProxyID: int64Ptr(1), Host: "app.example.com", SrcIP: "203.0.113.7",
			Method: "GET", Path: "/", Status: 200, Action: "allow"},
		{TS: hour.Add(2 * time.Minute), ProxyID: int64Ptr(1), Host: "app.example.com", SrcIP: "203.0.113.8",
			Method: "GET", Path: "/.env", Status: 403, Action: "block"},
	}); err != nil {
		t.Fatal(err)
	}

	if err := st.RollupUtilization(hour.Add(10*time.Minute), UtilSample{CPU: 10, MemUsed: 100, MemTotal: 1000, WANRx: 5}); err != nil {
		t.Fatal(err)
	}
	if err := st.RollupUtilization(hour.Add(20*time.Minute), UtilSample{CPU: 30, MemUsed: 300, MemTotal: 1000, WANRx: 15}); err != nil {
		t.Fatal(err)
	}

	rows, err := st.UtilizationHours(hour.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("hours = %+v, want one row", rows)
	}
	got := rows[0]
	if got.CPU != 20 || got.MemUsed != 200 || got.WANRx != 10 {
		t.Fatalf("hour = %+v, want the mean of the two samples", got)
	}
	if got.Reqs != 2 || got.Blocked != 1 {
		t.Fatalf("counts = %d/%d, want 2 requests and 1 block", got.Reqs, got.Blocked)
	}

	if err := st.DeleteUtilizationBefore(hour.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if rows, err = st.UtilizationHours(hour.Add(-time.Hour)); err != nil || len(rows) != 0 {
		t.Fatalf("after retention rows = %+v, err = %v", rows, err)
	}
}

// An upgrade already has event history: every hour the log holds gets a row with
// its request and block counts, and an hour that already has a live row keeps it.
func TestBackfillUtilizationFillsOnlyMissingHours(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	testProxy(t, st, "app.example.com")

	hour := time.Now().UTC().Truncate(time.Hour).Add(-3 * time.Hour)
	if err := st.InsertEvents([]model.Event{
		{TS: hour.Add(5 * time.Minute), ProxyID: int64Ptr(1), Host: "app.example.com", SrcIP: "203.0.113.7",
			Method: "GET", Path: "/", Status: 200, Action: "allow"},
		{TS: hour.Add(10 * time.Minute), ProxyID: int64Ptr(1), Host: "app.example.com", SrcIP: "203.0.113.8",
			Method: "GET", Path: "/.env", Status: 403, Action: "block"},
		{TS: hour.Add(time.Hour + 5*time.Minute), ProxyID: int64Ptr(1), Host: "app.example.com", SrcIP: "203.0.113.9",
			Method: "GET", Path: "/", Status: 200, Action: "allow"},
	}); err != nil {
		t.Fatal(err)
	}
	// The first hour already has a live row, so its counts must survive as they are.
	if err := st.RollupUtilization(hour.Add(20*time.Minute), UtilSample{CPU: 10}); err != nil {
		t.Fatal(err)
	}

	n, err := st.BackfillUtilization(hour.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("backfilled %d hours, want the one missing hour", n)
	}
	rows, err := st.UtilizationHours(hour.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("hours = %+v, want two", rows)
	}
	if got := rows[0]; got.Reqs != 2 || got.Blocked != 1 || got.Samples != 1 || got.CPU != 10 {
		t.Fatalf("live hour = %+v, want its own counts kept", got)
	}
	if got := rows[1]; got.Reqs != 1 || got.Blocked != 0 || got.Samples != 0 {
		t.Fatalf("backfilled hour = %+v, want counts only", got)
	}
	if n, err = st.BackfillUtilization(hour.Add(-time.Hour)); err != nil || n != 0 {
		t.Fatalf("a second backfill inserted %d rows, err = %v", n, err)
	}
}
