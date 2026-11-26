package scan_test

// This test runs the scanner through the real policy engine and proxy handler,
// not a fake published path: the WAN listener is the proxy itself, and the
// application behind it serves a leaking status endpoint. It proves the whole
// chain a page-started run relies on — the deny_paths block answers 403, the
// controlled path stops being a finding, and the finding a previous run opened
// is resolved — without the untracked demo harness.

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/botguard"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/gate"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/policy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/proxy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/scan"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/scantrust"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

// pipeline is one node: a store, the real policy, the real proxy and a
// published listener in front of it.
type pipeline struct {
	store     *store.Store
	policy    *policy.Engine
	trust     *scantrust.Registry
	bans      *ban.Engine
	proxy     *proxy.Server
	published string
	host      string
	denyPath  string
	openPath  string
}

func newPipeline(t *testing.T) *pipeline {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	box, err := wfcrypto.New(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	bans, err := ban.New(st, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	geo := geoip.Open(filepath.Join(dir, "geo"))
	profiles, err := st.ListProfiles()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.New(st, bans, nil, geo, waf.NewSet(profiles, log), log)
	if err != nil {
		t.Fatal(err)
	}
	trust := scantrust.New()
	pol.ScanTrust = trust.Valid

	// /actuator/env is the exposure a scan can close: no decoy covers it.
	// /.env is left open on purpose, so the test can show suppression is the
	// deny_paths control and not a stage that stopped reporting exposures.
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/actuator/env":
			_, _ = io.WriteString(w, `{"spring.datasource.password":"demo"}`)
		case "/.env":
			_, _ = io.WriteString(w, "DB_PASSWORD=demo")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	upstream := httptest.NewServer(app)
	t.Cleanup(upstream.Close)

	px, err := proxy.New(proxy.Deps{
		Store: st, Policy: pol, Gate: gate.New(st, box, bans, log),
		Bots: botguard.New(bytes.Repeat([]byte{0x42}, 32), bans, st, log), Bans: bans, Geo: geo,
		Metrics: metrics.New("", ""), Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	host := "app.example.com"
	id, err := st.CreateProxy(&model.Proxy{
		Hostname: host, Enabled: true, GateMode: "off",
		Fingerprint: "strict", WAFMode: "on", BotLevel: "off",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceUpstreams(id, []model.Upstream{
		{ProxyID: id, URL: upstream.URL, Weight: 1, Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := px.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	published := httptest.NewServer(px)
	t.Cleanup(published.Close)
	return &pipeline{
		store: st, policy: pol, trust: trust, bans: bans, proxy: px,
		published: published.URL, host: host,
		denyPath: "/actuator/env", openPath: "/.env",
	}
}

// run scans the target the way the API does, through the real published path.
func (p *pipeline) run(t *testing.T, trigger string) model.ScanRun {
	t.Helper()
	proxy, err := p.store.ProxyByHost(p.host)
	if err != nil {
		t.Fatal(err)
	}
	run, err := scan.Execute(context.Background(), scan.ExecuteDeps{
		Store: p.store, PerSecond: 50, ConsoleHost: "console.example.com",
		WANBase: func(string) string { return p.published },
		Trust:   p.trust, Bans: p.bans,
	}, *proxy, trigger, "tester")
	if err != nil {
		t.Fatalf("run %s: %v", trigger, err)
	}
	return run
}

// fetch asks the published listener for one path with the site's Host header.
func (p *pipeline) fetch(t *testing.T, path string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, p.published+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = p.host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func findingByKey(findings []model.ScanFinding, key string) *model.ScanFinding {
	for i := range findings {
		if findings[i].Key == key {
			return &findings[i]
		}
	}
	return nil
}

// A scan run through the real policy and proxy proves the one-click control:
// the path is open before deny_paths, the block answers 403 after it, the
// controlled path stops being reported, and the finding the earlier run opened
// is resolved — while the unblocked exposure stays open.
func TestExposureControlIsProvenThroughTheRealProxy(t *testing.T) {
	p := newPipeline(t)

	if status := p.fetch(t, p.denyPath); status != http.StatusOK {
		t.Fatalf("the app's %s answered %d before the block, want it reachable", p.denyPath, status)
	}
	first := p.run(t, scan.TriggerManual)
	if first.Skipped != "" {
		t.Fatalf("the first run was skipped: %s", first.Skipped)
	}
	findings, err := p.store.ListScanFindings("", "")
	if err != nil {
		t.Fatal(err)
	}
	controlled := findingByKey(findings, "exposure:"+p.denyPath)
	if controlled == nil || controlled.State != "open" {
		t.Fatalf("findings = %+v, want %s open before the block", findings, p.denyPath)
	}

	// Install the same control the finding's one-click action installs.
	proxy, err := p.store.ProxyByHost(p.host)
	if err != nil {
		t.Fatal(err)
	}
	proxy.DenyPaths = append(proxy.DenyPaths, p.denyPath)
	if err := p.store.UpdateProxy(proxy); err != nil {
		t.Fatal(err)
	}
	if err := p.policy.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := p.proxy.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if status := p.fetch(t, p.denyPath); status != http.StatusForbidden {
		t.Fatalf("the published %s answered %d after the block, want 403 from the proxy", p.denyPath, status)
	}

	second := p.run(t, scan.TriggerRemediation)
	if second.Skipped != "" {
		t.Fatalf("the retest was skipped: %s", second.Skipped)
	}
	evidence, err := p.store.ListScanEvidence(second.ID)
	if err != nil {
		t.Fatal(err)
	}
	var row *model.ScanEvidence
	for i := range evidence {
		if evidence[i].Class == "exposure" && evidence[i].Path == p.denyPath {
			row = &evidence[i]
		}
	}
	if row == nil || row.Verdict != string(scan.BlockedWAF) || row.WANStatus != http.StatusForbidden || row.UpStatus != http.StatusOK {
		t.Fatalf("retest evidence = %+v, want the published path refused while the app still served it", row)
	}
	if !scan.ExposureClosed(evidence, p.denyPath) {
		t.Fatalf("retest evidence = %+v, want it to prove %s closed", evidence, p.denyPath)
	}

	findings, err = p.store.ListScanFindings("", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := findingByKey(findings, "exposure:"+p.denyPath); got == nil || got.State != "resolved" {
		t.Fatalf("%s = %+v, want it resolved by the rerun's proof", p.denyPath, got)
	}
	if got := findingByKey(findings, "exposure:"+p.openPath); got == nil || got.State != "open" {
		t.Fatalf("%s = %+v, want the unblocked exposure still open", p.openPath, got)
	}
	if p.bans.Count() != 0 {
		t.Fatalf("the scan wrote %d ban(s) for its own source", p.bans.Count())
	}
}
