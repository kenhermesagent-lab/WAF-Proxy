package store

import (
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

	exported, err := st.ExportEvents(EventFilter{From: f.From, To: f.To, Stage: "decoy"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(exported) != 1 || exported[0].Path != "/.env" {
		t.Fatalf("exported = %+v", exported)
	}
}
