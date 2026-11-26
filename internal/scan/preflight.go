package scan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

const (
	// PathEdge means the published answer carried CF-Ray: a Cloudflare edge
	// fronted the probe.
	PathEdge = "edge"
	// PathLocal means nothing in front of this node answered. The run tested
	// this proxy's own WAF, never the operator's edge rules.
	PathLocal = "local"

	// ProbePathPrefix is the one path prefix attack traffic is addressed to.
	// Preflight proves it answers the application's own 404 before a body probe
	// is sent, so a WAF miss lands on a 404 handler and not on an action.
	ProbePathPrefix = "/.wafscan/"

	// StagePreflight, StageEdge and StageWAF label evidence rows.
	StagePreflight = "preflight"
	StageEdge      = "edge"
	StageWAF       = "waf"
)

const (
	// skipCatchAll is recorded on a body class when the probe path turned out to
	// be implemented.
	skipCatchAll = "not run: the probe path is implemented by a catch-all route"
	// skipControl is recorded on the rest of a class whose control was refused:
	// a blanket refusal cannot be told apart from a rule.
	skipControl = "not run: the control request for this class was refused"
)

// Check is one preflight observation.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Preflight is what the scanner established before it sent attack traffic. Path
// says which side the probes actually tested; BodyProbes says whether a body may
// be sent to the probe path at all.
type Preflight struct {
	Host       string
	ProbePath  string
	Path       string
	BodyProbes bool
	Checks     []Check
	// Endpoint is the published endpoint that answered, and Fallback explains a
	// listener dial when the hostname did not. Both are empty when the hostname
	// answered directly.
	Endpoint string
	Fallback string
	// Skip is why no attack probe may run. Empty means the run can proceed.
	Skip string
}

func (p *Preflight) add(name string, ok bool, detail string) {
	p.Checks = append(p.Checks, Check{Name: name, OK: ok, Detail: detail})
}

// Target is one hostname to scan: its proxy record, the published endpoint, the
// upstream the probes compare, and the listener fallback used when the hostname
// does not resolve or its port is unreachable.
type Target struct {
	Proxy    model.Proxy
	WAN      Endpoint
	Fallback Endpoint
	Upstream Endpoint
}

// NewProbePath builds the path attack traffic is addressed to. The segment is
// random so a cached 404 from an earlier run cannot stand in for the
// application's own answer.
func NewProbePath() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("scan: random probe path: %w", err)
	}
	return ProbePathPrefix + hex.EncodeToString(b[:]), nil
}

// RunPreflight establishes the path taken and whether attack traffic may be
// sent. It sends harmless requests only: no payload, no body, nothing a rule
// could mistake for the attack the run is about to test.
func (r *Runner) RunPreflight(ctx context.Context, target Target) (*Preflight, error) {
	path, err := NewProbePath()
	if err != nil {
		return nil, err
	}
	pf := &Preflight{Host: target.Proxy.Hostname, ProbePath: path, Path: PathLocal}
	proxy := target.Proxy

	pf.add("site enabled", proxy.Enabled && !proxy.Maintenance,
		fmt.Sprintf("enabled=%t maintenance=%t", proxy.Enabled, proxy.Maintenance))
	switch {
	case !proxy.Enabled:
		pf.Skip = "the site is disabled"
	case proxy.Maintenance:
		pf.Skip = "the site is in maintenance"
	}
	if n := len(proxy.BodySkip); n > 0 {
		pf.add("streaming routes", true,
			fmt.Sprintf("%d path(s) stream without inspection; they are excluded", n))
	} else {
		pf.add("streaming routes", true, "none")
	}
	mode := proxy.GateMode
	if mode == "" {
		mode = "off"
	}
	pf.add("gate mode", true, mode)
	if pf.Skip != "" {
		return pf, nil
	}

	// A control-shaped request on the probe path. It answers, it carries no
	// payload, and its headers say whether an edge is in front of this node.
	probe := r.tagProbe(Probe{
		Stage: StagePreflight, Class: "probe-path", Method: http.MethodGet,
		Path: path, Query: "id=1",
	}, 0)
	wan, err := r.send(ctx, r.wanClient, r.wan, probe)
	if err != nil {
		primary := r.unreachableNote("published", r.wan, err)
		fallback := target.Fallback
		if fallback.URL == nil || !fallbackOn(err) {
			pf.add("published path", false, primary)
			pf.Skip = primary
			return pf, nil
		}
		// The hostname does not resolve or its port does not answer. The node's
		// own listener is the published path when no edge fronts it, and the
		// same hostname travels as Host and SNI.
		client := probeClient(false, fallback.TLSName, fallback.Roots)
		fb, fbErr := r.send(ctx, client, fallback, probe)
		if fbErr != nil {
			note := primary + "; the listener endpoint " + fallback.Label() + " did not answer: " + shortError(fbErr)
			pf.add("published path", false, note)
			pf.Skip = note
			return pf, nil
		}
		r.wan, r.wanClient = fallback, client
		wan = fb
		pf.Endpoint = fallback.Label()
		pf.Fallback = primary
		pf.add("published path", true, fmt.Sprintf(
			"HTTP %d via %s; %s", wan.status, fallback.Label(), primary))
	} else {
		pf.Endpoint = r.wan.Label()
		pf.add("published path", true, fmt.Sprintf("HTTP %d via %s", wan.status, pf.Endpoint))
	}
	pf.add("probe path reachable", !wanRefusal(wan.status), probePathNote(wan.status))
	if wan.header.Get("CF-Ray") != "" {
		pf.Path = PathEdge
		pf.add("path taken", true, "edge: the answer carried CF-Ray")
	} else {
		pf.add("path taken", true, "local: no CF-Ray, so this is this node's own WAF")
	}

	up, err := r.send(ctx, r.upClient, r.upstream, probe)
	if err != nil {
		note := r.unreachableNote("upstream", r.upstream, err)
		if pf.Fallback != "" {
			note += "; the published path was dialled at " + pf.Endpoint + " after " + pf.Fallback
		}
		pf.add("upstream", false, note)
		pf.Skip = note
		return pf, nil
	}
	pf.add("upstream", true, fmt.Sprintf("HTTP %d", up.status))
	switch {
	case up.status == http.StatusNotFound || up.status == http.StatusGone:
		pf.BodyProbes = true
		pf.add("probe path", true, "the application answers 404; body probes are addressed there")
	case up.status >= 200 && up.status < 300:
		pf.add("probe path", false, fmt.Sprintf(
			"the application answers HTTP %d from a catch-all route; body probes are not sent", up.status))
	default:
		pf.add("probe path", false, fmt.Sprintf(
			"the application answers HTTP %d, not a 404; body probes are not sent", up.status))
	}
	return pf, nil
}

// fallbackOn reports a failure the listener may answer: the hostname did not
// resolve, or the dial was refused or timed out. A TLS certificate error is not
// one — the listener presents the same name and certificate — so it is reported
// instead of retried.
func fallbackOn(err error) bool {
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return true
	}
	var op *net.OpError
	if errors.As(err, &op) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// ProbeClass is one probe family: a benign control and the payloads that follow
// it. A refused control voids the class, so the control always runs first.
type ProbeClass struct {
	Control Probe
	Probes  []Probe
	// Body marks a class whose payload travels in a request body. It may only
	// run once preflight has proven the probe path unimplemented.
	Body bool
}

// probePathNote explains a published answer to the probe path, because a refusal
// there skips every class that control-checks the same path.
func probePathNote(status int) string {
	if wanRefusal(status) {
		return fmt.Sprintf("the published path refuses the probe path with HTTP %d; its classes will be skipped", status)
	}
	return "the published path answers the probe path"
}

// classes is every probe family in the catalogue.
func classes(probePath, host string) []ProbeClass {
	return append(edgeClasses(probePath, host), wafClasses(probePath)...)
}

// Catalogue builds the probes for a run. Preflight decides what may be sent: a
// body class without a proven 404 and a disabled site are recorded as not run
// rather than sent.
func Catalogue(pf *Preflight) []Probe {
	var out []Probe
	for _, c := range classes(pf.ProbePath, pf.Host) {
		skip := pf.Skip
		if skip == "" && c.Body && !pf.BodyProbes {
			skip = skipCatchAll
		}
		out = append(out, sendable(c.Control, skip))
		for _, p := range c.Probes {
			out = append(out, sendable(p, skip))
		}
	}
	return out
}

func sendable(p Probe, skip string) Probe {
	if skip != "" {
		p.Skip = skip
	}
	return p
}

// getClass probes a method on the probe path. The control is a GET of the same
// path: the point is that the path answers at all.
func getClass(stage, class, probePath, method string) ProbeClass {
	return ProbeClass{
		Control: Probe{Stage: stage, Class: class, Method: http.MethodGet, Path: probePath, Control: true},
		Probes:  []Probe{{Stage: stage, Class: class, Method: method, Path: probePath}},
	}
}

// hostClass sends the same request under another spelling of the hostname, so a
// rule that matches the literal Host is visible.
func hostClass(stage, class, probePath, hostname string) ProbeClass {
	return ProbeClass{
		Control: Probe{Stage: stage, Class: class, Method: http.MethodGet, Path: probePath, Control: true},
		Probes: []Probe{{Stage: stage, Class: class, Method: http.MethodGet, Path: probePath,
			HostOverride: hostname}},
	}
}

// pathClass appends an encoded shape to the probe path.
func pathClass(stage, class, probePath, suffix string) ProbeClass {
	return ProbeClass{
		Control: Probe{Stage: stage, Class: class, Method: http.MethodGet, Path: probePath, Control: true},
		Probes:  []Probe{{Stage: stage, Class: class, Method: http.MethodGet, Path: probePath + suffix}},
	}
}

// queryClass puts a payload in one query parameter, with the same parameter and
// a harmless value as its control.
func queryClass(stage, class, probePath, param, payload string) ProbeClass {
	return ProbeClass{
		Control: Probe{Stage: stage, Class: class, Method: http.MethodGet, Path: probePath,
			Query: param + "=1", Control: true},
		Probes: []Probe{{Stage: stage, Class: class, Method: http.MethodGet, Path: probePath,
			Query: param + "=" + url.QueryEscape(payload)}},
	}
}

// headerClass puts a payload in one header, with a harmless value in the same
// header as its control.
func headerClass(stage, class, probePath, name, payload, control string) ProbeClass {
	return ProbeClass{
		Control: Probe{Stage: stage, Class: class, Method: http.MethodGet, Path: probePath,
			Header: http.Header{name: {control}}, Control: true},
		Probes: []Probe{{Stage: stage, Class: class, Method: http.MethodGet, Path: probePath,
			Header: http.Header{name: {payload}}}},
	}
}

// bodyClass POSTs a payload to the probe path. The control POSTs a valid body of
// the same content type, because a refusal of a malformed control would void a
// class that was never tested.
func bodyClass(stage, class, probePath, contentType, controlBody, body string) ProbeClass {
	return ProbeClass{
		Body: true,
		Control: Probe{Stage: stage, Class: class, Method: http.MethodPost, Path: probePath,
			Header: http.Header{"Content-Type": {contentType}}, Body: controlBody, Control: true},
		Probes: []Probe{{Stage: stage, Class: class, Method: http.MethodPost, Path: probePath,
			Header: http.Header{"Content-Type": {contentType}}, Body: body}},
	}
}

// rawClass sends a wire shape net/http cannot build. It is only ever sent to
// the published path, and reason says so in the evidence row.
func rawClass(stage, class, probePath, method, raw string, body bool, reason string) ProbeClass {
	return ProbeClass{
		Body:    body,
		Control: Probe{Stage: stage, Class: class, Method: http.MethodGet, Path: probePath, Control: true},
		Probes: []Probe{{Stage: stage, Class: class, Method: method, Path: probePath,
			Raw: raw, WANOnly: true, Note: reason}},
	}
}
