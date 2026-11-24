package store

import (
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// TestReachSnapshotSplitsAllowedFromBlocked pins the distinction the attack map
// draws: requests that landed on a login page counted separately from the ones
// refused, and a detect-only match counted as a near miss rather than a block.
func TestReachSnapshotSplitsAllowedFromBlocked(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	pid := testProxy(t, st, "app.example.com")
	events := []model.Event{
		{TS: now.Add(-5 * time.Minute), SrcIP: "198.51.100.20", Country: "US", Host: "app.example.com",
			Method: "GET", Path: "/login", Status: 200, Action: "allow", Stage: "route"},
		{TS: now.Add(-4 * time.Minute), SrcIP: "203.0.113.7", Country: "RU", Host: "app.example.com",
			Method: "POST", Path: "/login", Status: 401, Action: "allow", Stage: "route"},
		{TS: now.Add(-3 * time.Minute), SrcIP: "203.0.113.7", Country: "RU", Host: "app.example.com",
			Method: "GET", Path: "/admin/users", Status: 200, Action: "allow", Stage: "route"},
		{TS: now.Add(-2 * time.Minute), SrcIP: "198.51.100.20", Country: "US", Host: "app.example.com",
			Method: "GET", Path: "/about", Status: 200, Action: "allow", Stage: "route"},
		{TS: now.Add(-time.Minute), SrcIP: "203.0.113.7", Country: "RU", Host: "app.example.com",
			Method: "GET", Path: "/login", Status: 403, Action: "ban", Stage: "decoy"},
		{TS: now, SrcIP: "203.0.113.9", Country: "NL", Host: "app.example.com",
			Method: "GET", Path: "/.env", Status: 200, Action: "log", Stage: "waf",
			RuleID: "930130", RuleMsg: "Restricted File Access Attempt"},
	}
	for i := range events {
		events[i].ProxyID = &pid
	}
	if err := st.InsertEvents(events); err != nil {
		t.Fatal(err)
	}

	got, err := st.ReachSnapshot(now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got.Allowed != 4 || got.Reached != 3 {
		t.Fatalf("allowed/reached = %d/%d, want 4/3", got.Allowed, got.Reached)
	}
	if len(got.Endpoints) != 3 {
		t.Fatalf("endpoints = %d, want 3: %+v", len(got.Endpoints), got.Endpoints)
	}
	// The refused POST to /login is a block, not something that landed.
	for _, e := range got.Endpoints {
		if e.Status == 403 {
			t.Fatalf("blocked request counted as reach: %+v", e)
		}
	}
	if len(got.Sources) != 2 {
		t.Fatalf("sources = %d, want 2: %+v", len(got.Sources), got.Sources)
	}
	if got.Sources[0].IP != "203.0.113.7" || got.Sources[0].Count != 2 || got.Sources[0].Country != "RU" {
		t.Fatalf("unexpected busiest source: %+v", got.Sources[0])
	}
	if len(got.NearMiss) != 1 || got.NearMiss[0].RuleID != "930130" || got.NearMiss[0].Count != 1 {
		t.Fatalf("near miss = %+v, want the logged WAF rule", got.NearMiss)
	}
}
