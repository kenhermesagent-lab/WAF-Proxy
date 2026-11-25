package scan

// fingerprint.go identifies the application behind the proxy from its banners
// and public status endpoints, then checks the paths that exist only because
// they hold credentials. The identification is what the CVE join needs; the
// exposure checks keep the status code and header names and never the body,
// because the body is the credential.

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

//go:embed fingerprints.json
var fingerprintFS embed.FS

const (
	// StageBackend labels fingerprint, exposure and CVE-join evidence rows.
	StageBackend = "backend"
	// fingerprintBodyLimit is how much of a page is matched against the shipped
	// signatures. The body is never stored.
	fingerprintBodyLimit = 512 << 10
)

// fingerprintPaths are the unauthenticated requests the backend stage reads.
// Every one of them is a page a first-time visitor may load.
var fingerprintPaths = []string{"/", "/status.php", "/api/health", "/login"}

// exposurePaths exist precisely because they hold credentials or a status page
// that names the application.
var exposurePaths = []string{"/.git/config", "/.env", "/server-status", "/actuator/env"}

// Component is one product identified behind the proxy. Package and Ecosystem
// are set for the products OSV can answer for; the rest can be fingerprinted
// but not joined to advisories.
type Component struct {
	Product    string `json:"product"`
	Label      string `json:"label,omitempty"`
	Version    string `json:"version,omitempty"`
	Confidence string `json:"confidence"`
	Source     string `json:"source"`
	Package    string `json:"package,omitempty"`
	Ecosystem  string `json:"ecosystem,omitempty"`
}

// fingerprintSignature is one entry of the embedded table.
type fingerprintSignature struct {
	Product        string `json:"product"`
	Label          string `json:"label"`
	Endpoint       string `json:"endpoint,omitempty"`
	Header         string `json:"header,omitempty"`
	Pattern        string `json:"pattern"`
	VersionPattern string `json:"version_pattern,omitempty"`
	Confidence     string `json:"confidence"`
	Package        string `json:"package,omitempty"`
	Ecosystem      string `json:"ecosystem,omitempty"`
}

type fingerprintMatcher struct {
	sig     fingerprintSignature
	match   *regexp.Regexp
	version *regexp.Regexp
}

// fingerprintMatchers parses the embedded table once. A bad table is a build
// error, not a runtime surprise the operator has to discover.
var fingerprintMatchers = mustFingerprintMatchers()

func mustFingerprintMatchers() []fingerprintMatcher {
	raw, err := fingerprintFS.ReadFile("fingerprints.json")
	if err != nil {
		panic("scan: read fingerprints.json: " + err.Error())
	}
	var table struct {
		Signatures []fingerprintSignature `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &table); err != nil {
		panic("scan: parse fingerprints.json: " + err.Error())
	}
	if len(table.Signatures) == 0 {
		panic("scan: fingerprints.json has no signatures")
	}
	out := make([]fingerprintMatcher, 0, len(table.Signatures))
	for _, sig := range table.Signatures {
		m := fingerprintMatcher{sig: sig, match: regexp.MustCompile(sig.Pattern)}
		if sig.VersionPattern != "" {
			m.version = regexp.MustCompile(sig.VersionPattern)
		}
		out = append(out, m)
	}
	return out
}

// observation is one unauthenticated page fetched from the upstream.
type observation struct {
	path   string
	status int
	header http.Header
	body   []byte
}

// matchFingerprints names every product the observations support. A product
// matched by several signatures keeps its strongest answer.
func matchFingerprints(obs []observation) []Component {
	best := map[string]Component{}
	for _, m := range fingerprintMatchers {
		for _, o := range obs {
			if m.sig.Endpoint != "" && m.sig.Endpoint != o.path {
				continue
			}
			source, version, ok := m.observe(o)
			if !ok {
				continue
			}
			c := Component{
				Product: m.sig.Product, Label: m.sig.Label, Version: version,
				Confidence: m.sig.Confidence, Source: source,
				Package: m.sig.Package, Ecosystem: m.sig.Ecosystem,
			}
			if prev, seen := best[c.Product]; !seen || betterComponent(c, prev) {
				best[c.Product] = c
			}
		}
	}
	out := make([]Component, 0, len(best))
	for _, c := range best {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Product < out[j].Product })
	return out
}

func (m fingerprintMatcher) observe(o observation) (string, string, bool) {
	var haystack, source string
	if m.sig.Header != "" {
		value := o.header.Get(m.sig.Header)
		if value == "" {
			return "", "", false
		}
		haystack, source = value, "the "+m.sig.Header+" header"
	} else {
		body := o.body
		if len(body) > fingerprintBodyLimit {
			body = body[:fingerprintBodyLimit]
		}
		haystack, source = string(body), o.path
	}
	match := m.match.FindStringSubmatch(haystack)
	if match == nil {
		return "", "", false
	}
	version := ""
	if m.version != nil {
		if vm := m.version.FindStringSubmatch(haystack); vm != nil {
			version = strings.TrimSpace(vm[1])
		}
	} else if len(match) > 1 {
		version = strings.TrimSpace(match[1])
	}
	return source, version, true
}

func betterComponent(a, b Component) bool {
	if confidenceRank(a.Confidence) != confidenceRank(b.Confidence) {
		return confidenceRank(a.Confidence) > confidenceRank(b.Confidence)
	}
	return a.Version != "" && b.Version == ""
}

func confidenceRank(confidence string) int {
	switch confidence {
	case "high":
		return 3
	case "medium":
		return 2
	}
	return 1
}

// Fingerprint reads the upstream's banners and status endpoints. An application
// that matches nothing is reported unknown, never clean.
func (r *Runner) Fingerprint(ctx context.Context, target Target) ([]model.ScanEvidence, []Component) {
	var obs []observation
	requested := make([]string, 0, len(fingerprintPaths))
	for _, path := range fingerprintPaths {
		p := Probe{Stage: StageBackend, Class: "fingerprint", Method: http.MethodGet, Path: path}
		a, err := r.send(ctx, r.upClient, target.Upstream, p)
		if err != nil {
			continue
		}
		requested = append(requested, fmt.Sprintf("%s HTTP %d", path, a.status))
		obs = append(obs, observation{path: path, status: a.status, header: a.header, body: a.body})
	}
	probe := Probe{Stage: StageBackend, Class: "fingerprint", Method: http.MethodGet, Path: "/"}
	if len(obs) == 0 {
		return []model.ScanEvidence{evidenceRow(r, nil, probe, NotRun,
			"the upstream did not answer any fingerprint path")}, nil
	}
	comps := matchFingerprints(obs)
	if len(comps) == 0 {
		return []model.ScanEvidence{evidenceRow(r, nil, probe, Unknown,
			"no shipped signature matched: "+strings.Join(requested, ", "))}, nil
	}
	return []model.ScanEvidence{evidenceRow(r, nil, probe, Passed,
		identified(comps)+" from "+strings.Join(requested, ", "))}, comps
}

func identified(comps []Component) string {
	parts := make([]string, 0, len(comps))
	for _, c := range comps {
		if c.Version != "" {
			parts = append(parts, c.Label+" "+c.Version)
			continue
		}
		parts = append(parts, c.Label)
	}
	return "identified " + strings.Join(parts, ", ")
}

// exposure checks the paths that exist only to leak: no body byte is kept, only
// the status, the length and the names of the headers.
func (r *Runner) exposure(ctx context.Context, target Target) ([]model.ScanEvidence, []model.ScanFinding) {
	var rows []model.ScanEvidence
	var findings []model.ScanFinding
	for _, path := range exposurePaths {
		p := Probe{Stage: StageBackend, Class: "exposure", Method: http.MethodGet, Path: path}
		up, err := r.send(ctx, r.upClient, target.Upstream, p)
		if err != nil {
			rows = append(rows, evidenceAt(r, rows, p, nil, NotRun, "the upstream did not answer: "+shortError(err)))
			continue
		}
		if up.status < 200 || up.status >= 300 || len(up.body) == 0 {
			rows = append(rows, evidenceAt(r, rows, p, &up, Passed,
				fmt.Sprintf("the application did not serve this path (HTTP %d)", up.status)))
			continue
		}
		served := fmt.Sprintf("the application served HTTP %d, %d bytes, headers: %s",
			up.status, len(up.body), headerNames(up.header))
		wan, wanErr := r.send(ctx, r.wanClient, r.wan, p)
		if wanErr == nil && wanRefusal(wan.status) {
			ev := evidenceAt(r, rows, p, &up, BlockedWAF,
				served+fmt.Sprintf("; the published path refuses it with HTTP %d", wan.status))
			ev.WANStatus, ev.WANHash = wan.status, wan.hash()
			rows = append(rows, ev)
			findings = append(findings, exposureFinding(path, SeverityMedium,
				served+"; blocked at the edge, but the file itself is still there"))
			continue
		}
		note := served
		if wanErr != nil {
			note += "; the published path did not answer: " + shortError(wanErr)
		}
		rows = append(rows, evidenceAt(r, rows, p, &up, ReachedBackend, note))
		findings = append(findings, exposureFinding(path, exposureSeverity(path), note))
	}
	return rows, findings
}

func exposureFinding(path, severity, note string) model.ScanFinding {
	return model.ScanFinding{
		Key: "exposure:" + path, Stage: StageBackend, Class: "exposure",
		Title:    "The application serves " + path,
		Severity: severity, Recommendation: "compensate",
		Note: note + "; remove it from the web root, or keep the published path refused until it is gone",
	}
}

func exposureSeverity(path string) string {
	if path == "/.env" || path == "/.git/config" {
		return SeverityHigh
	}
	return SeverityMedium
}

// headerNames lists the header names of an answer. Values are never kept: a
// Set-Cookie or a location can carry a credential. Only names that are plain
// tokens are echoed, so a malicious answer cannot smuggle a payload into a
// stored note through a header name.
func headerNames(h http.Header) string {
	names := make([]string, 0, len(h))
	for name := range h {
		if len(name) <= 40 && strings.IndexFunc(name, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-')
		}) < 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	const limit = 12
	if len(names) > limit {
		names = append(names[:limit], "…")
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// RunBackend runs the unauthenticated backend stage and returns its evidence
// plus the findings the CVE join produced. A component the join could not
// assess is reported unknown, never clean.
func (r *Runner) RunBackend(ctx context.Context, target Target, intel Intel) ([]model.ScanEvidence, []model.ScanFinding) {
	rows, comps := r.Fingerprint(ctx, target)
	exposureRows, findings := r.exposure(ctx, target)
	rows = append(rows, exposureRows...)
	joined, report := intel.Join(ctx, comps)
	findings = append(findings, joined...)

	note := fmt.Sprintf("%d component(s), %d advisor(ies), %d known-exploited match(es)",
		report.Components, report.Advisories, report.KEV)
	verdict := Passed
	if report.Unknown {
		verdict = Unknown
		note += "; unknown: " + strings.Join(report.Reasons, "; ")
	}
	p := Probe{Stage: StageBackend, Class: "cve-join", Method: configMethod, Path: target.Proxy.Hostname}
	rows = append(rows, evidenceAt(r, rows, p, nil, verdict, note))
	// The stage's rows come from three helpers, so number them once here: the
	// evidence key is (run, seq) and duplicate seqs would collide.
	for i := range rows {
		rows[i].Seq = i
	}
	return rows, findings
}

// evidenceRow builds a row whose sequence number keeps the run's evidence keys
// unique.
func evidenceRow(r *Runner, rows []model.ScanEvidence, p Probe, v Verdict, note string) model.ScanEvidence {
	return r.row(len(rows), p, string(v), note)
}

// evidenceAt is evidenceRow for an answer that was compared, so the statuses
// travel with the verdict.
func evidenceAt(r *Runner, rows []model.ScanEvidence, p Probe, a *answer, v Verdict, note string) model.ScanEvidence {
	ev := evidenceRow(r, rows, p, v, note)
	if a != nil {
		ev.UpStatus = a.status
		ev.UpHash = a.hash()
	}
	return ev
}
