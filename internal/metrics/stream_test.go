package metrics

import (
	"strings"
	"testing"
)

func TestStreamsExposition(t *testing.T) {
	var b strings.Builder
	Streams(&b, []StreamCounters{
		{Service: "valheim", Sessions: 2, BytesIn: 100, BytesOut: 200, PacketsIn: 7, PacketsOut: 9,
			Refused: map[string]uint64{"cap": 3, "allow": 1}},
		{Service: "plex", Sessions: 1, BytesIn: 5, BytesOut: 6, PacketsIn: 1, PacketsOut: 1},
	})
	out := b.String()
	for _, want := range []string{
		`# TYPE wafproxy_stream_sessions gauge`,
		`wafproxy_stream_sessions{service="plex"} 1`,
		`wafproxy_stream_sessions{service="valheim"} 2`,
		`wafproxy_stream_bytes_total{service="valheim",direction="in"} 100`,
		`wafproxy_stream_bytes_total{service="valheim",direction="out"} 200`,
		`wafproxy_stream_packets_total{service="valheim",direction="out"} 9`,
		`wafproxy_stream_refused_total{service="valheim",reason="allow"} 1`,
		`wafproxy_stream_refused_total{service="valheim",reason="cap"} 3`,
		`wafproxy_stream_cap_hits_total{service="valheim"} 3`,
		`wafproxy_stream_cap_hits_total{service="plex"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("exposition missing %q:\n%s", want, out)
		}
	}
	// Sorted by service, so a scrape diff does not churn.
	if strings.Index(out, `service="plex"`) > strings.Index(out, `service="valheim"`) {
		t.Fatalf("services are not sorted:\n%s", out)
	}

	// Nothing listening means no stream families at all, rather than a row of
	// zeros for every catalog entry.
	var empty strings.Builder
	Streams(&empty, nil)
	if empty.Len() != 0 {
		t.Fatalf("empty exposition = %q", empty.String())
	}
}
