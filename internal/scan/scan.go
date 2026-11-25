// Package scan attacks this node's own published hostnames read-only and
// proves what each layer did by comparing the published answer with the
// upstream one. Nothing here writes to an application.
package scan

import (
	"net/http"
	"net/url"
)

// Verdict is what one probe proved.
type Verdict string

const (
	// BlockedWAF means the published path refused a request the upstream would
	// have answered.
	BlockedWAF Verdict = "blocked-waf"
	// BlockedGate means the access gate challenged the request before the app.
	BlockedGate Verdict = "blocked-gate"
	// ReachedBackend means the two answers match: nothing in front of the app
	// stopped this class of request.
	ReachedBackend Verdict = "reached-backend"
	// Inconclusive means the answers differed for a reason unrelated to the
	// request, so the probe proves nothing either way.
	Inconclusive Verdict = "inconclusive"
	// NotRun means the probe was refused by the runner or did not answer.
	NotRun Verdict = "not-run"
)

// Probe is one request sent through the published path and to the upstream.
type Probe struct {
	Stage  string
	Class  string
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   string
	// Control marks the benign request for a class. If the control is refused,
	// every block in that class proves nothing.
	Control bool
}

// Endpoint is one side of the comparison: where the scanner connects, and the
// Host the request must claim. URL is the root a probe path is appended to.
type Endpoint struct {
	URL  *url.URL
	Host string
	// Insecure skips certificate verification for a backend that uses a
	// self-signed one. The published side never sets it.
	Insecure bool
}
