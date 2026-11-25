package uptime

import (
	"testing"
	"time"
)

func TestHistoryRecordsOutageAndLatency(t *testing.T) {
	now := time.Now()
	st := &targetState{Target: Target{ID: "upstream:1", ProxyID: 4, URL: "http://192.0.2.10:8090"}}

	up := func(at time.Time, ms int64) {
		st.Target = Target{ID: st.ID, ProxyID: st.ProxyID, URL: st.URL, State: StateUp,
			StatusCode: 200, LatencyMS: ms}
		st.recordSample(at)
		st.trackIncident(at)
	}
	down := func(at time.Time, msg string) {
		st.Target = Target{ID: st.ID, ProxyID: st.ProxyID, URL: st.URL, State: StateDown,
			LatencyMS: 0, Error: msg}
		st.recordSample(at)
		st.trackIncident(at)
	}

	up(now.Add(-300*time.Second), 10)
	down(now.Add(-240*time.Second), "connection refused")
	down(now.Add(-210*time.Second), "connection refused")
	up(now.Add(-180*time.Second), 12)
	up(now.Add(-150*time.Second), 900)
	up(now.Add(-120*time.Second), 800)
	up(now.Add(-90*time.Second), 11)

	if len(st.incidents) != 1 {
		t.Fatalf("incidents = %d, want 1", len(st.incidents))
	}
	if st.incidents[0].Checks != 2 || st.incidents[0].End == nil {
		t.Fatalf("incident = %+v, want 2 checks and an end", st.incidents[0])
	}
	if st.incidents[0].Error != "connection refused" {
		t.Fatalf("incident error = %q", st.incidents[0].Error)
	}
	lat := stats(st.samples)
	if lat.Checks != 7 || lat.Up != 5 {
		t.Fatalf("stats = %+v, want 7 checks and 5 up", lat)
	}
	if lat.P50MS != 12 || lat.MaxMS != 900 {
		t.Fatalf("percentiles = %+v, want p50 12 and max 900", lat)
	}
	slow := slowSpans(st.samples, lat)
	if len(slow) != 1 || slow[0].Checks != 2 || slow[0].MaxMS != 900 {
		t.Fatalf("slow = %+v, want one span of 2 probes peaking at 900 ms", slow)
	}
}
