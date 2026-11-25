package scan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// newBackendRun points both sides at one fake application, which is all the
// backend stage needs.
func newBackendRun(t *testing.T, handler http.HandlerFunc) (Target, *Runner) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	target := Target{
		Proxy:    model.Proxy{ID: 1, Hostname: "app.example.com", Enabled: true},
		WAN:      Endpoint{URL: u, Host: "app.example.com"},
		Upstream: Endpoint{URL: u, Host: "app.example.com"},
	}
	return target, NewRunner(target.WAN, target.Upstream, 0)
}

// fakeAdvisories answers as OSV would, without a network.
type fakeAdvisories struct {
	list []Advisory
	err  error
}

func (f fakeAdvisories) Advisories(context.Context, string, string, string) ([]Advisory, error) {
	return f.list, f.err
}

// A public status endpoint is enough to name a product and its exact version,
// which is what the CVE join needs to query.
func TestFingerprintFromStatusEndpoint(t *testing.T) {
	target, runner := newBackendRun(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status.php" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"installed":true,"version":"27.1.2.4","versionstring":"27.1.2","productname":"Nextcloud"}`)
	})

	rows, comps := runner.Fingerprint(context.Background(), target)
	if len(comps) != 1 || comps[0].Product != "nextcloud" || comps[0].Version != "27.1.2" {
		t.Fatalf("components = %+v, want nextcloud 27.1.2", comps)
	}
	if len(rows) != 1 || rows[0].Verdict != string(Passed) || !strings.Contains(rows[0].Note, "Nextcloud 27.1.2") {
		t.Fatalf("fingerprint evidence = %+v, want one passed row naming Nextcloud 27.1.2", rows)
	}
}

// A stale KEV snapshot must never turn "not listed" into "not exploited".
func TestStaleKEVMarksUnknownNeverClean(t *testing.T) {
	component := Component{
		Product: "grafana", Label: "Grafana", Version: "10.2.0",
		Package: "github.com/grafana/grafana", Ecosystem: "Go", Confidence: "high",
	}
	advisories := fakeAdvisories{list: []Advisory{
		{ID: "GHSA-aaaa", Aliases: []string{"CVE-2024-0001"}, Summary: "Test advisory", CVSS: 7.5},
	}}
	entries := map[string]KEVEntry{}
	fresh := &KEV{FetchedAt: time.Now(), SHA256: "fresh", Entries: entries}
	stale := &KEV{FetchedAt: time.Now().Add(-KEVStaleAfter - time.Hour), SHA256: "stale", Entries: entries}

	freshFindings, freshReport := Intel{KEV: fresh, Advisories: advisories}.Join(context.Background(), []Component{component})
	if freshReport.Unknown {
		t.Fatalf("a fresh KEV snapshot was reported unknown: %v", freshReport.Reasons)
	}
	if len(freshFindings) != 1 || freshFindings[0].Exploitation != ExploitationNone {
		t.Fatalf("fresh join = %+v, want one finding that is not known-exploited", freshFindings)
	}

	findings, report := Intel{KEV: stale, Advisories: advisories}.Join(context.Background(), []Component{component})
	if !report.Unknown {
		t.Fatal("a stale KEV snapshot was not reported unknown")
	}
	if len(findings) != 1 || findings[0].Exploitation != ExploitationUnknown {
		t.Fatalf("stale join = %+v, want the exploitation status unknown", findings)
	}
	for _, f := range findings {
		if f.Exploitation == ExploitationNone {
			t.Fatalf("a stale snapshot claimed %s is not exploited", f.Key)
		}
	}
	if !strings.Contains(strings.Join(report.Reasons, " "), "stale") {
		t.Fatalf("the report does not say why it is unknown: %v", report.Reasons)
	}
}

// A malformed download is rejected whole, and the last good snapshot stays in
// place: a partial parse would answer "not exploited" for the missing entries.
func TestMalformedKEVRejectedAtomically(t *testing.T) {
	var current string
	unchanged := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unchanged && r.Header.Get("If-None-Match") == `"kev-1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"kev-1"`)
		_, _ = io.WriteString(w, current)
	}))
	defer srv.Close()

	client := &KEVClient{URL: srv.URL, Client: srv.Client(), Now: time.Now}
	current = `{"count":1,"vulnerabilities":[{"cveID":"CVE-2024-0001","vendorProject":"Acme","product":"Widget","vulnerabilityName":"Widget RCE","dateAdded":"2024-01-02","dueDate":"2024-01-23"}]}`
	first, changed, err := client.Refresh(context.Background(), nil)
	if err != nil || !changed || first == nil {
		t.Fatalf("first refresh = %v, %t, %v", first, changed, err)
	}
	if first.Len() != 1 || first.SHA256 == "" || first.ETag == "" {
		t.Fatalf("first snapshot = %+v, want one entry, a hash and an ETag", first)
	}

	// The count disagrees with the list, so the file is refused rather than
	// trusted entry by entry.
	current = `{"count":3,"vulnerabilities":[{"cveID":"CVE-2024-0002","dateAdded":"2024-01-03"},{"cveID":"CVE-2024-0003","dateAdded":"2024-01-03"}]}`
	second, changed, err := client.Refresh(context.Background(), first)
	if err == nil || changed || second != nil {
		t.Fatalf("a malformed snapshot was accepted: %v, %t, %v", second, changed, err)
	}
	if first.Len() != 1 || first.SHA256 == "" {
		t.Fatal("the refused snapshot changed the good one")
	}

	// An unchanged feed answers 304: the same data is kept and only its
	// confirmation time moves.
	unchanged = true
	third, changed, err := client.Refresh(context.Background(), first)
	if err != nil || changed || third == nil || third.Len() != 1 || third.SHA256 != first.SHA256 {
		t.Fatalf("304 refresh = %+v, %t, %v; want the previous snapshot", third, changed, err)
	}
}

// The paths that exist to leak credentials are reported by status, length and
// header names. The body is the credential, so it is never stored.
func TestNoBodyStoredForSecretBearingPaths(t *testing.T) {
	const secret = "DB_PASSWORD=hunter2-super-secret"
	target, runner := newBackendRun(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			w.Header().Set("X-Leaky-Body", "yes")
			_, _ = io.WriteString(w, secret)
		case "/.git/config":
			_, _ = io.WriteString(w, "[core]\n\tbare = false\n")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	rows, findings := runner.RunBackend(context.Background(), target, Intel{})
	dump := fmt.Sprintf("%+v\n%+v", rows, findings)
	if strings.Contains(dump, "hunter2") || strings.Contains(dump, "DB_PASSWORD") {
		t.Fatalf("evidence stored the file body:\n%s", dump)
	}
	var row *model.ScanEvidence
	for i := range rows {
		if rows[i].Class == "exposure" && rows[i].Path == "/.env" {
			row = &rows[i]
		}
	}
	if row == nil || row.Verdict != string(ReachedBackend) || !strings.Contains(row.Note, "bytes") {
		t.Fatalf("/.env exposure = %+v, want a reached-backend row with its size", row)
	}
	found := false
	for _, f := range findings {
		if f.Key == "exposure:/.env" && f.Severity == SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Fatalf("no high finding for the exposed .env: %+v", findings)
	}
}

// An empty OSV answer cannot be told apart from a package name or version OSV
// does not know, so it is unknown, never clean.
func TestEmptyOSVAnswerIsUnknownNotClean(t *testing.T) {
	component := Component{
		Product: "grafana", Label: "Grafana", Version: "10.2.0",
		Package: "github.com/grafana/grafana", Ecosystem: "Go", Confidence: "high",
	}
	fresh := &KEV{FetchedAt: time.Now(), SHA256: "fresh", Entries: map[string]KEVEntry{}}

	findings, report := Intel{KEV: fresh, Advisories: fakeAdvisories{}}.Join(context.Background(), []Component{component})
	if !report.Unknown {
		t.Fatal("an empty OSV answer passed as clean")
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none from an empty answer", findings)
	}
	if reasons := strings.Join(report.Reasons, " "); !strings.Contains(reasons, "unknown, not clean") {
		t.Fatalf("the report does not say why it is unknown: %s", reasons)
	}
}

// OSV's Go ranges are semantic versions with a leading v; the fingerprint table
// reads a bare version from a page, so the query must carry the prefix.
func TestOSVNormalizesGoVersion(t *testing.T) {
	var bodies []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()

	osv := &OSV{BaseURL: srv.URL, Client: srv.Client(), Cache: NewOSVCache(1 << 20)}
	if _, err := osv.Advisories(context.Background(), "github.com/grafana/grafana", "Go", "10.2.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := osv.Advisories(context.Background(), "org.jenkins-ci.main:jenkins-core", "Maven", "2.401.3"); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 {
		t.Fatalf("made %d OSV queries, want 2", len(bodies))
	}
	if !strings.Contains(bodies[0], `"version":"v10.2.0"`) {
		t.Fatalf("Go query = %s, want the version prefixed with v", bodies[0])
	}
	if !strings.Contains(bodies[1], `"version":"2.401.3"`) {
		t.Fatalf("Maven query = %s, want the version unchanged", bodies[1])
	}
}

// The advisory cache never grows past its cap, however many versions a scan
// meets, and it drops the least recently used answer first.
func TestOSVCacheStaysUnderCap(t *testing.T) {
	cache := NewOSVCache(2000)
	big := []Advisory{{ID: strings.Repeat("X", 400), CVSS: 7.5}}
	for i := 0; i < 20; i++ {
		cache.put(fmt.Sprintf("key-%02d", i), big)
	}
	if got := cache.Bytes(); got > 2000 {
		t.Fatalf("cache holds %d bytes, cap 2000", got)
	}
	if cache.Len() == 0 {
		t.Fatal("the cache evicted everything")
	}
	if _, ok := cache.get("key-19"); !ok {
		t.Fatal("the newest answer was evicted")
	}
	if _, ok := cache.get("key-00"); ok {
		t.Fatal("the oldest answer survived the cap")
	}
}

// An OSV answer becomes a CVSS score and a CVE id, and the second lookup is
// served from the cache.
func TestOSVQueryParsesCVSSAndAliases(t *testing.T) {
	var requests int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/query" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(&requests, 1)
		_, _ = io.WriteString(w, `{"vulns":[{"id":"GHSA-x","aliases":["CVE-2024-1234"],"summary":"Test advisory","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],"published":"2024-05-01T00:00:00Z"}]}`)
	}))
	defer srv.Close()

	osv := &OSV{BaseURL: srv.URL, Client: srv.Client(), Cache: NewOSVCache(1 << 20)}
	for i := 0; i < 2; i++ {
		advisories, err := osv.Advisories(context.Background(), "pkg", "Go", "1.2.3")
		if err != nil {
			t.Fatal(err)
		}
		if len(advisories) != 1 || advisories[0].CVSS != 9.8 {
			t.Fatalf("advisories = %+v, want one at CVSS 9.8", advisories)
		}
		if ids := advisories[0].CVEIDs(); len(ids) != 1 || ids[0] != "CVE-2024-1234" {
			t.Fatalf("CVE ids = %v, want CVE-2024-1234", ids)
		}
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("the cache sent %d OSV requests, want one", got)
	}
}
