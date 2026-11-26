package scan

// run.go is the run path: resolve one proxy's endpoints, run every stage, store
// what was proved, and alert on what changed. The API's run button and the
// scheduler's tick call this same function.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// TriggerManual names an operator-started run.
const TriggerManual = "manual"

// Notifier delivers a run's findings. A nil notifier keeps the run silent.
type Notifier interface {
	EnqueueSecurityFindings([]model.ScanFinding)
	EnqueueSecurityResolved([]model.ScanFinding)
}

// ExecuteDeps is everything a run needs from outside itself.
type ExecuteDeps struct {
	Store       *store.Store
	Box         *crypto.Box
	Notify      Notifier
	OSV         AdvisorySource
	PerSecond   int
	ConsoleHost string
	// WANBase builds the published endpoint for a hostname; nil means
	// https://<hostname>, which is what a real deployment uses.
	WANBase func(hostname string) string
	Now     func() time.Time
}

// sharedOSV keeps the advisory cache across runs.
var sharedOSV = NewOSV()

// DefaultPerSecond is the probe rate a site scans at until it sets its own.
const DefaultPerSecond = 12

// ProbesPerSecond reads a site's saved rate, clamped to the documented range.
// The manual run and the scheduler both use it, so a limit set once applies to
// every run.
func ProbesPerSecond(st *store.Store) int {
	if raw, err := st.GetSetting("security_probes_per_second"); err == nil {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 && n <= 50 {
			return n
		}
	}
	return DefaultPerSecond
}

// Paused reports whether the site's single pause switch is on.
func Paused(st *store.Store) bool {
	raw, err := st.GetSetting("security_paused")
	return err == nil && raw == "1"
}

// Execute scans one proxy and records the run. A missing upstream or a refused
// preflight is recorded as a skipped run, not an error the operator has to
// guess at.
func Execute(ctx context.Context, d ExecuteDeps, proxy model.Proxy, trigger, actor string) (model.ScanRun, error) {
	now := time.Now()
	if d.Now != nil {
		now = d.Now()
	}
	run := model.ScanRun{SiteID: d.Store.SiteID(), Target: proxy.Hostname, Trigger: trigger, Actor: actor, StartedAt: now}
	target, targetErr := resolveTarget(d, proxy)
	id, err := d.Store.CreateScanRun(&run)
	if err != nil {
		return run, err
	}
	run.ID = id
	if targetErr != nil {
		run.Skipped = targetErr.Error()
		return finishRun(d, run, now, nil, targetErr)
	}

	runner := NewRunner(target.WAN, target.Upstream, d.PerSecond)
	runner.RunID = id
	preflight, err := runner.RunPreflight(ctx, target)
	if err != nil {
		return finishRun(d, run, now, nil, err)
	}
	run.Path = preflight.Path
	if preflight.Skip != "" {
		run.Skipped = preflight.Skip
		return finishRun(d, run, now, nil, nil)
	}

	evidence, runErr := runner.Run(ctx, Catalogue(preflight))
	evidence = append(evidence, runner.RunGate(ctx, target, gateOptions(d, proxy))...)
	backend, findings := runner.RunBackend(ctx, target, Intel{
		KEV: loadKEV(d.Store), Advisories: advisorySource(d), Now: d.Now,
	})
	evidence = append(evidence, backend...)
	for i := range evidence {
		evidence[i].RunID = id
		evidence[i].Seq = i
	}
	if err := d.Store.AddScanEvidence(evidence); err != nil {
		return finishRun(d, run, now, evidence, err)
	}
	if runErr != nil {
		// A sustained refusal aborted the run; the rows so far are still evidence.
		run.Skipped = shortError(runErr)
	}
	opened, resolved, err := d.Store.MergeScanFindings(run.SiteID, proxy.Hostname, findings, now)
	if err != nil {
		return finishRun(d, run, now, evidence, err)
	}
	if d.Notify != nil {
		d.Notify.EnqueueSecurityFindings(opened)
		d.Notify.EnqueueSecurityResolved(resolved)
	}
	return finishRun(d, run, now, evidence, nil)
}

// finishRun closes the run with the time it actually ended. Using the start
// timestamp here made every run's duration zero.
func finishRun(d ExecuteDeps, run model.ScanRun, started time.Time, evidence []model.ScanEvidence, runErr error) (model.ScanRun, error) {
	end := time.Now()
	if d.Now != nil {
		end = d.Now()
	}
	if end.Before(started) {
		end = started
	}
	verdicts := verdictCounts(evidence)
	if err := d.Store.FinishScanRun(run.ID, end, verdicts, run.Path, run.Skipped); err != nil {
		return run, err
	}
	run.EndedAt = &end
	run.Verdicts = verdicts
	return run, runErr
}

func verdictCounts(rows []model.ScanEvidence) string {
	counts := map[string]int{}
	for _, row := range rows {
		counts[row.Verdict]++
	}
	raw, _ := json.Marshal(counts)
	return string(raw)
}

// resolveTarget builds the two endpoints from the proxy record. The upstream is the
// first enabled address the operator saved; the published side is the hostname,
// never a free-form URL from the request.
func resolveTarget(d ExecuteDeps, proxy model.Proxy) (Target, error) {
	base := "https://" + proxy.Hostname
	if d.WANBase != nil {
		base = d.WANBase(proxy.Hostname)
	}
	wan, err := url.Parse(base)
	if err != nil || wan.Host == "" {
		return Target{}, fmt.Errorf("the published endpoint is not a URL: %q", base)
	}
	ups, err := d.Store.ListUpstreams(proxy.ID)
	if err != nil {
		return Target{}, err
	}
	for _, up := range ups {
		if !up.Enabled {
			continue
		}
		u, err := url.Parse(up.URL)
		if err != nil || u.Host == "" {
			continue
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			u.Scheme = "http"
		}
		return Target{
			Proxy:    proxy,
			WAN:      Endpoint{URL: wan, Host: proxy.Hostname},
			Upstream: Endpoint{URL: u, Host: proxy.Hostname},
		}, nil
	}
	return Target{}, errors.New("the hostname has no enabled upstream")
}

// gateOptions signs in with the scan-only account bound to this hostname, and
// counts the failures already in the ladder's window against the budget.
func gateOptions(d ExecuteDeps, proxy model.Proxy) GateOptions {
	opts := GateOptions{ConsoleHost: d.ConsoleHost}
	if d.Store == nil {
		return opts
	}
	opts.SignOut = func(username string) error { return d.Store.DeleteGateSessionsFor(username) }
	if perProxy, err := d.Store.GateFailuresSince(time.Now().Add(-10 * time.Minute)); err == nil {
		opts.PriorFailures = perProxy[proxy.ID]
	}
	user, err := d.Store.ScanGateUser(proxy.ID)
	if err != nil || user == nil || d.Box == nil {
		return opts
	}
	if secret, err := d.Box.Open(user.ScanSecret); err == nil && secret != "" {
		opts.Account = &GateAccount{Username: user.Username, Password: secret}
	}
	return opts
}

func loadKEV(st *store.Store) *KEV {
	kev, err := LoadKEV(st)
	if err != nil {
		return nil
	}
	return kev
}

func advisorySource(d ExecuteDeps) AdvisorySource {
	if d.OSV != nil {
		return d.OSV
	}
	return sharedOSV
}
