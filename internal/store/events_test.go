package store

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func TestIPSummariesAndExport(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	events := []model.Event{
		{TS: now.Add(-3 * time.Minute), SrcIP: "203.0.113.7", Country: "RU", ASN: 123, Host: "app.example.com",
			Method: "GET", Path: "/", Status: 200, Action: "allow", Stage: "route", BytesOut: 10},
		{TS: now.Add(-2 * time.Minute), SrcIP: "203.0.113.7", Country: "RU", ASN: 123, Host: "app.example.com",
			Method: "GET", Path: "/.env", Status: 403, Action: "ban", Stage: "decoy", BytesOut: 0},
		{TS: now.Add(-time.Minute), SrcIP: "198.51.100.20", Country: "US", ASN: 456, Host: "app.example.com",
			Method: "POST", Path: "/login", Status: 200, Action: "allow", Stage: "route", BytesOut: 99},
	}
	pid := testProxy(t, st, "app.example.com")
	for i := range events {
		events[i].ProxyID = &pid
	}
	if err := st.InsertEvents(events); err != nil {
		t.Fatal(err)
	}

	f := EventFilter{From: now.Add(-time.Hour), To: now.Add(time.Minute)}
	list, err := st.IPSummaries(f, "203.0.113", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("summaries = %d, want 1", len(list))
	}
	if got := list[0]; got.IP != "203.0.113.7" || got.Requests != 2 || got.Blocked != 1 || got.Hosts != 1 || got.BytesOut != 10 {
		t.Fatalf("unexpected summary: %+v", got)
	}

	one, err := st.IPSummary("203.0.113.7", f.From, f.To)
	if err != nil || one.Requests != 2 {
		t.Fatalf("single summary = %+v (%v)", one, err)
	}
	empty, err := st.IPSummary("192.0.2.99", f.From, f.To)
	if err != nil || empty.IP != "192.0.2.99" || empty.Requests != 0 {
		t.Fatalf("missing IP summary = %+v (%v)", empty, err)
	}

	exported := []model.Event{}
	err = st.EachEvent(EventFilter{From: f.From, To: f.To, Stage: "decoy"}, 100, func(e model.Event) error {
		exported = append(exported, e)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(exported) != 1 || exported[0].Path != "/.env" {
		t.Fatalf("exported = %+v", exported)
	}
	// A callback error stops the walk instead of buffering the rest.
	calls := 0
	err = st.EachEvent(f, 100, func(model.Event) error {
		calls++
		return io.ErrUnexpectedEOF
	})
	if !errors.Is(err, io.ErrUnexpectedEOF) || calls != 1 {
		t.Fatalf("callback abort = %d calls, %v", calls, err)
	}
}

func TestEventTotals(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	events := []model.Event{
		{TS: now.Add(-5 * time.Minute), SrcIP: "203.0.113.7", Host: "app.example.com", Action: "allow", Stage: "route"},
		{TS: now.Add(-4 * time.Minute), SrcIP: "203.0.113.7", Host: "app.example.com", Action: "ban", Stage: "decoy"},
		{TS: now.Add(-3 * time.Minute), SrcIP: "203.0.113.7", Host: "api.example.com", Action: "challenge", Stage: "waf"},
		{TS: now.Add(-2 * time.Minute), SrcIP: "198.51.100.20", Host: "other.example.com", Action: "allow", Stage: "route"},
		{TS: now.Add(-time.Minute), SrcIP: "198.51.100.20", Host: "app.example.com", Action: "block", Stage: "waf"},
	}
	pid := testProxy(t, st, "app.example.com")
	for i := range events {
		events[i].ProxyID = &pid
	}
	if err := st.InsertEvents(events); err != nil {
		t.Fatal(err)
	}

	from, to := now.Add(-time.Hour), now.Add(time.Minute)
	host, err := st.EventTotals(EventFilter{From: from, To: to, Host: "app.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if want := (EventTotals{Total: 3, Blocked: 2, Sources: 2, Hosts: 1}); host != want {
		t.Fatalf("host totals = %+v, want %+v", host, want)
	}

	blocked, err := st.EventTotals(EventFilter{From: from, To: to, BlockedOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := (EventTotals{Total: 3, Blocked: 3, Sources: 2, Hosts: 2}); blocked != want {
		t.Fatalf("blocked totals = %+v, want %+v", blocked, want)
	}

	empty, err := st.EventTotals(EventFilter{From: from, To: to, Host: "missing.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if empty != (EventTotals{}) {
		t.Fatalf("unmatched totals = %+v, want zero", empty)
	}
}

// testProxy registers the hostname the event fixtures belong to. Events are
// scoped through their proxy, so a fixture without one is host-level noise.
func testProxy(t *testing.T, st *Store, host string) int64 {
	t.Helper()
	id, err := st.CreateProxy(&model.Proxy{Hostname: host, Enabled: true, WAFMode: "inherit", Fingerprint: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// The query is what the WAF inspected, so the log and its replay have to carry
// it rather than showing a path that would have been allowed.
func TestEventQueryRoundTrips(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	pid := testProxy(t, st, "app.example.com")
	now := time.Now().UTC()
	if err := st.InsertEvents([]model.Event{{
		TS: now, ProxyID: &pid, Host: "app.example.com", SrcIP: "203.0.113.7",
		Method: "GET", Path: "/search", Query: "q=1%27+OR+%271%27%3D%271", Status: 403,
		Action: "block", Stage: "waf", RuleID: "942100", RuleMsg: "sqli: SQL Injection Attack",
	}}); err != nil {
		t.Fatal(err)
	}
	list, _, err := st.QueryEvents(EventFilter{From: now.Add(-time.Minute), To: now.Add(time.Minute)})
	if err != nil || len(list) != 1 {
		t.Fatalf("events = %d, %v", len(list), err)
	}
	if list[0].Path != "/search" || list[0].Query != "q=1%27+OR+%271%27%3D%271" {
		t.Fatalf("path/query = %q/%q", list[0].Path, list[0].Query)
	}
	if list[0].RuleID != "942100" || list[0].RuleMsg != "sqli: SQL Injection Attack" {
		t.Fatalf("rule = %q/%q", list[0].RuleID, list[0].RuleMsg)
	}
}
