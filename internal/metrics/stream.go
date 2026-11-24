package metrics

import (
	"fmt"
	"io"
	"sort"
)

// StreamCounters is one forwarder's live totals: what the status page shows,
// gathered once per scrape.
type StreamCounters struct {
	Service    string
	Sessions   int64
	BytesIn    uint64
	BytesOut   uint64
	PacketsIn  uint64
	PacketsOut uint64
	// Refused is keyed by reason (ban, list, allow, cap).
	Refused map[string]uint64
}

// Streams writes the forwarder families. Only listening services are passed in,
// so an unconfigured catalog entry does not look like an idle port.
func Streams(w io.Writer, streams []StreamCounters) {
	if len(streams) == 0 {
		return
	}
	sort.Slice(streams, func(i, j int) bool { return streams[i].Service < streams[j].Service })

	fmt.Fprintln(w, "# HELP wafproxy_stream_sessions Live sessions on a forwarder, TCP connections plus UDP sessions.")
	fmt.Fprintln(w, "# TYPE wafproxy_stream_sessions gauge")
	for _, s := range streams {
		fmt.Fprintf(w, "wafproxy_stream_sessions{service=%q} %d\n", s.Service, s.Sessions)
	}

	fmt.Fprintln(w, "# HELP wafproxy_stream_bytes_total Bytes forwarded, by direction.")
	fmt.Fprintln(w, "# TYPE wafproxy_stream_bytes_total counter")
	for _, s := range streams {
		fmt.Fprintf(w, "wafproxy_stream_bytes_total{service=%q,direction=\"in\"} %d\n", s.Service, s.BytesIn)
		fmt.Fprintf(w, "wafproxy_stream_bytes_total{service=%q,direction=\"out\"} %d\n", s.Service, s.BytesOut)
	}

	fmt.Fprintln(w, "# HELP wafproxy_stream_packets_total Packets forwarded, by direction. A TCP packet is one read or write.")
	fmt.Fprintln(w, "# TYPE wafproxy_stream_packets_total counter")
	for _, s := range streams {
		fmt.Fprintf(w, "wafproxy_stream_packets_total{service=%q,direction=\"in\"} %d\n", s.Service, s.PacketsIn)
		fmt.Fprintf(w, "wafproxy_stream_packets_total{service=%q,direction=\"out\"} %d\n", s.Service, s.PacketsOut)
	}

	fmt.Fprintln(w, "# HELP wafproxy_stream_refused_total Refused sessions, by the rule that refused them.")
	fmt.Fprintln(w, "# TYPE wafproxy_stream_refused_total counter")
	for _, s := range streams {
		reasons := make([]string, 0, len(s.Refused))
		for reason := range s.Refused {
			reasons = append(reasons, reason)
		}
		sort.Strings(reasons)
		for _, reason := range reasons {
			fmt.Fprintf(w, "wafproxy_stream_refused_total{service=%q,reason=%q} %d\n", s.Service, reason, s.Refused[reason])
		}
	}

	fmt.Fprintln(w, "# HELP wafproxy_stream_cap_hits_total Connections refused because a session cap was full.")
	fmt.Fprintln(w, "# TYPE wafproxy_stream_cap_hits_total counter")
	for _, s := range streams {
		fmt.Fprintf(w, "wafproxy_stream_cap_hits_total{service=%q} %d\n", s.Service, s.Refused["cap"])
	}
}
