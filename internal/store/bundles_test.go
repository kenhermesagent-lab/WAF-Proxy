package store

import (
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func TestBundleHitsOnlyCountsBundleRuleIDs(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	events := []model.Event{
		{TS: now, Stage: "waf", RuleID: "990417", RuleMsg: "template injection", SrcIP: "203.0.113.9", Action: "block"},
		{TS: now.Add(-time.Hour), Stage: "waf", RuleID: "990417", RuleMsg: "template injection", SrcIP: "203.0.113.10", Action: "block"},
		{TS: now, Stage: "waf", RuleID: "990123", RuleMsg: "union select", SrcIP: "203.0.113.9", Action: "log"},
		// Not a bundle rule, and outside the window: none of these may appear
		// in the hit table.
		{TS: now, Stage: "waf", RuleID: "942100", SrcIP: "203.0.113.9", Action: "block"},
		// A real CRS ID above 960000, which the bundle range must stay clear of.
		{TS: now, Stage: "waf", RuleID: "980170", SrcIP: "203.0.113.9", Action: "log"},
		// A logged bundle rule whose request continued upstream still counts:
		// the event is named after the later stage but keeps the rule ID.
		{TS: now, Stage: "upstream", RuleID: "990417", SrcIP: "203.0.113.11", Action: "allow"},
		{TS: now.Add(-48 * time.Hour), Stage: "waf", RuleID: "990417", SrcIP: "203.0.113.12", Action: "block"},
	}
	if err := st.InsertEvents(events); err != nil {
		t.Fatal(err)
	}

	hits, err := st.BundleHits(now.Add(-24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 {
		t.Fatalf("hits = %+v, want two rules", hits)
	}
	byRule := map[int]RuleHit{}
	for _, h := range hits {
		byRule[h.RuleID] = h
	}
	if got := byRule[990417]; got.Hits != 3 || got.Addresses != 3 || got.Message != "template injection" {
		t.Fatalf("990417 = %+v", got)
	}
	if got := byRule[990123]; got.Hits != 1 || got.Addresses != 1 {
		t.Fatalf("990123 = %+v", got)
	}
	// The outcome columns have to follow the event action, not the profile
	// mode: 990417 was blocked both times, 990123 was only logged.
	if got := byRule[990417]; got.Blocked != 2 || got.Logged != 1 {
		t.Fatalf("990417 outcomes = %+v, want two blocks and a log", got)
	}
	if got := byRule[990123]; got.Blocked != 0 || got.Logged != 1 {
		t.Fatalf("990123 outcomes = %+v, want one log", got)
	}
}
