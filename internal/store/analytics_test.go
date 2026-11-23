package store

import (
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func TestAnalyticsRangeGroupsTrafficAndOutcomes(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Analytics resolves host names through proxies, so the events' proxy ids
	// have to exist.
	testProxy(t, st, "app.example.com")
	testProxy(t, st, "media.example.com")

	now := time.Now().UTC().Truncate(time.Hour)
	events := []model.Event{
		{TS: now.Add(5 * time.Minute), ProxyID: int64Ptr(1), Host: "app.example.com", Country: "US", Method: "GET",
			Path: "/", Status: 200, Action: "allow", Stage: "route", BytesOut: 100},
		{TS: now.Add(10 * time.Minute), ProxyID: int64Ptr(1), Host: "app.example.com", Country: "US", Method: "GET",
			Path: "/.env", Status: 403, Action: "block", Stage: "decoy", BytesOut: 20},
		{TS: now.Add(20 * time.Minute), ProxyID: int64Ptr(2), Host: "media.example.com", Country: "DE", Method: "GET",
			Path: "/", Status: 200, Action: "allow", Stage: "route", BytesOut: 300},
	}
	if err := st.InsertEvents(events); err != nil {
		t.Fatal(err)
	}

	got, err := st.AnalyticsRange(now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got.Totals.Requests != 3 || got.Totals.Blocked != 1 {
		t.Fatalf("totals = %+v", got.Totals)
	}
	if len(got.Series) != 1 || got.Series[0].Requests != 3 || got.Series[0].Success != 2 || got.Series[0].Errors != 1 {
		t.Fatalf("series = %+v", got.Series)
	}
	if len(got.Proxies) != 2 || got.Proxies[0].ProxyID != 1 || got.Proxies[0].Requests != 2 {
		t.Fatalf("proxies = %+v", got.Proxies)
	}
	if len(got.Countries) != 2 || got.Countries[0].Name != "US" {
		t.Fatalf("countries = %+v", got.Countries)
	}
}

func int64Ptr(v int64) *int64 { return &v }
