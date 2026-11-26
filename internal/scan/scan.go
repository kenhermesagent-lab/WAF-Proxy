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
	// NotBlocked means a WAN-only probe was not refused. Its upstream half is
	// skipped on purpose, so this says the edge accepted the shape, not that the
	// application was reached.
	NotBlocked Verdict = "not-blocked"
	// Passed means a gate check whose expectation held and which observed no
	// attack: cookie rotation, uniform failures, an armed ladder.
	Passed Verdict = "passed"
	// Failed means a gate check that should have held did not. It is a finding,
	// not a probe that reached the application.
	Failed Verdict = "failed"
	// NotApplicable means the site's mode makes the check meaningless, such as
	// the session probes on an external forward-auth provider.
	NotApplicable Verdict = "not-applicable"
	// Unknown means the answer could not be established: a feed was stale, the
	// application could not be identified, or an advisory lookup failed. It is
	// never a clean result.
	Unknown Verdict = "unknown"
)

// Finding severities, from docs/SECURITY-SCAN.md §4.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
	SeverityUnknown  = "unknown"
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
	// the rest of the class is not sent: a blanket refusal cannot be told apart
	// from a rule.
	Control bool
	// Skip is why the probe is not sent. Preflight and the catalogue set it, and
	// it becomes the evidence note.
	Skip string
	// WANOnly marks a probe that is never replayed at the upstream. Note says
	// why, because the missing half has to be visible in the report.
	WANOnly bool
	// Raw is the complete wire request for a shape net/http cannot build. It is
	// only ever written to the published endpoint.
	Raw string
	// HostOverride replaces the Host header for casing and trailing-dot probes
	// that must still reach the same site.
	HostOverride string
	// Note is stored with the evidence row when the verdict needs explaining.
	Note string
}

// Endpoint is one side of the comparison: where the scanner connects, and the
// Host the request must claim. URL is the root a probe path is appended to.
type Endpoint struct {
	URL  *url.URL
	Host string
	// TLSName is the name the certificate is checked against when URL.Host is a
	// dial address (the listener) rather than the site's own name. Empty uses
	// URL.Host.
	TLSName string
	// Insecure skips certificate verification for a backend that uses a
	// self-signed one. The published side never sets it.
	Insecure bool
}

// Label names the endpoint a probe dialled and the Host it claimed, so a
// failure can say which address and port were tried instead of only that
// "the published path did not answer".
func (e Endpoint) Label() string {
	if e.URL == nil {
		return e.Host
	}
	addr := e.URL.Host
	if addr == "" {
		addr = e.Host
	}
	scheme := e.URL.Scheme
	if scheme == "" {
		scheme = "http"
	}
	label := scheme + "://" + addr
	if e.Host != "" && e.Host != addr {
		label += " (Host: " + e.Host + ")"
	}
	return label
}
