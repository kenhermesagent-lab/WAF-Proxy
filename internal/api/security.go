package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/scan"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/scantrust"
)

const securityMaxTargets = 4

// securityRunAbandonedAfter is well past the five-minute run budget: a run
// with no end after this long had its process die and will never finish.
const securityRunAbandonedAfter = 15 * time.Minute

// markAbandoned flags unfinished runs old enough that nothing can still be
// working on them, so the page never shows a dead run as running.
func markAbandoned(runs []model.ScanRun) []model.ScanRun {
	now := time.Now()
	for i := range runs {
		if runs[i].EndedAt == nil && now.Sub(runs[i].StartedAt) > securityRunAbandonedAfter {
			runs[i].Abandoned = true
		}
	}
	return runs
}

// getSecurityOverview reports the site's posture, its open findings and what
// each vulnerability source last answered. A feed that is stale makes the
// posture unknown; only a run that found nothing and a fresh feed is covered.
func (s *Server) getSecurityOverview(w http.ResponseWriter, r *http.Request) {
	findings, err := s.db(r).ListScanFindings("", "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	runs, err := s.db(r).ListScanRuns(5)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	runs = markAbandoned(runs)
	sources, err := securityFeedSources(s.db(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	open, severities := 0, map[string]int{}
	for _, f := range findings {
		if f.State != "" && f.State != "open" {
			continue
		}
		open++
		severities[f.Severity]++
	}
	posture := "covered"
	switch {
	case open == 0 && len(runs) == 0:
		posture = "unknown"
	case hasExposure(findings):
		posture = "exposed"
	default:
		for _, src := range sources {
			if src.Stale {
				posture = "unknown"
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"posture": posture, "open_findings": open, "severities": severities,
		"findings": findings, "runs": runs, "sources": sources,
	})
}

func hasExposure(findings []model.ScanFinding) bool {
	for _, f := range findings {
		if f.State != "" && f.State != "open" {
			continue
		}
		if f.Severity == scan.SeverityCritical || f.Severity == scan.SeverityHigh {
			return true
		}
	}
	return false
}

func (s *Server) listSecurityRuns(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	runs, err := s.db(r).ListScanRuns(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": markAbandoned(runs)})
}

func (s *Server) getSecurityRun(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	runs, err := s.db(r).ListScanRuns(200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	runs = markAbandoned(runs)
	var run *model.ScanRun
	for i := range runs {
		if runs[i].ID == id {
			run = &runs[i]
			break
		}
	}
	if run == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	evidence, err := s.db(r).ListScanEvidence(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"run": run, "evidence": evidence})
}

// securityRunRefused explains why this node cannot start a scan right now.
// A standalone install and an active node both scan; only a standby refuses,
// because two nodes scanning would double the traffic and the gate's failure
// budget. The pause switch stops both the button and a remediation retest.
func (s *Server) securityRunRefused(r *http.Request) string {
	if s.securityPaused(r) {
		return "security scanning is paused"
	}
	if s.haStatus != nil {
		switch s.haStatus().Role {
		case "", "leader", "standalone", "active":
		default:
			return "only the active node runs scans"
		}
	}
	return ""
}

// createSecurityRun starts a scan of targets the signed-in site may read. A
// foreign site's proxy is a 404, never a scan.
func (s *Server) createSecurityRun(w http.ResponseWriter, r *http.Request) {
	if msg := s.securityRunRefused(r); msg != "" {
		writeError(w, http.StatusConflict, msg)
		return
	}
	var in struct {
		Targets []int64 `json:"targets"`
	}
	if err := decode(r, &in); err != nil || len(in.Targets) == 0 {
		writeError(w, http.StatusBadRequest, "at least one target is required")
		return
	}
	if len(in.Targets) > securityMaxTargets {
		writeError(w, http.StatusBadRequest, "at most four targets per run")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	sess := sessionFrom(r)
	deps := s.securityDeps(r)
	runs := make([]model.ScanRun, 0, len(in.Targets))
	for _, id := range in.Targets {
		proxy, err := s.db(r).GetProxy(id)
		if err != nil {
			writeError(w, http.StatusNotFound, "target not found")
			return
		}
		run, err := scan.Execute(ctx, deps, *proxy, scan.TriggerManual, sess.Username)
		if err != nil && run.ID == 0 {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		s.db(r).AddAudit(sess.Username, "security.run", proxy.Hostname, clientIP(r))
		runs = append(runs, run)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"runs": runs})
}

// remediateSecurityFinding installs the concrete control that closes an
// exposure finding — this host refuses the leaking path before the gate and
// the WAF — then reruns the target. The finding is resolved only when the new
// run's own evidence proves the path is no longer served; a skipped, failed or
// still-reachable rerun leaves it open.
func (s *Server) remediateSecurityFinding(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	exposedPath, ok := strings.CutPrefix(key, "exposure:")
	if !ok || !scan.IsExposurePath(exposedPath) {
		writeError(w, http.StatusBadRequest, "only an exposure finding can be closed this way")
		return
	}
	if msg := s.securityRunRefused(r); msg != "" {
		writeError(w, http.StatusConflict, msg)
		return
	}
	findings, err := s.db(r).ListScanFindings("", "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	var current *model.ScanFinding
	for i := range findings {
		if findings[i].Key == key {
			current = &findings[i]
			break
		}
	}
	if current == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if current.Class != "exposure" {
		writeError(w, http.StatusBadRequest, "only an exposure finding can be closed this way")
		return
	}
	if current.State != "" && current.State != "open" {
		writeError(w, http.StatusConflict, "only an open finding is remediated; reopen it first")
		return
	}
	proxy, err := s.db(r).ProxyByHost(current.Target)
	if err != nil {
		writeError(w, http.StatusNotFound, "the finding's hostname no longer exists")
		return
	}

	// The control is a per-host path block, so closing "actuator/env" cannot
	// affect any other hostname. It is idempotent: clicking twice adds no
	// duplicate and still retests.
	if !scan.PathBlocked(proxy.DenyPaths, exposedPath) {
		proxy.DenyPaths = append(proxy.DenyPaths, exposedPath)
		if err := s.db(r).UpdateProxy(proxy); err != nil {
			writeError(w, http.StatusInternalServerError, "cannot save the block")
			return
		}
		s.reload(r.Context())
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	sess := sessionFrom(r)
	run, err := scan.Execute(ctx, s.securityDeps(r), *proxy, scan.TriggerRemediation, sess.Username)
	s.db(r).AddAudit(sess.Username, "security.remediate", key+" "+proxy.Hostname, clientIP(r))
	if err != nil && run.ID == 0 {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	evidence, _ := s.db(r).ListScanEvidence(run.ID)
	proved := scan.ExposureClosed(evidence, exposedPath)
	state := "open"
	if proved {
		state = "resolved"
	}
	// A run whose backend stage could not answer leaves no finding behind, and
	// the merge treats that as resolved. The evidence is what decides here, so
	// an unproved path is put back to open.
	if err := s.db(r).UpdateScanFinding(key, state, nil); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	latest, err := s.db(r).ListScanFindings("", "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	var finding *model.ScanFinding
	for i := range latest {
		if latest[i].Key == key {
			finding = &latest[i]
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"run": run, "finding": finding, "proved": proved})
}

func (s *Server) listSecurityFindings(w http.ResponseWriter, r *http.Request) {
	findings, err := s.db(r).ListScanFindings(r.URL.Query().Get("state"), r.URL.Query().Get("severity"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": findings})
}

func (s *Server) patchSecurityFinding(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if strings.TrimSpace(key) == "" {
		writeError(w, http.StatusBadRequest, "a finding key is required")
		return
	}
	var in struct {
		State  string  `json:"state"`
		Reason *string `json:"reason"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if in.State != "" && in.State != "open" && in.State != "accepted" && in.State != "resolved" {
		writeError(w, http.StatusBadRequest, "state must be open, accepted or resolved")
		return
	}
	// Accepting a finding is an explicit risk decision, so the API requires the
	// reason the page asks for: the page is not the only client.
	if in.State == "accepted" && (in.Reason == nil || strings.TrimSpace(*in.Reason) == "") {
		writeError(w, http.StatusBadRequest, "a reason is required to accept a finding")
		return
	}
	findings, err := s.db(r).ListScanFindings("", "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	var current *model.ScanFinding
	for i := range findings {
		if findings[i].Key == key {
			current = &findings[i]
			break
		}
	}
	if current == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	state := current.State
	if in.State != "" {
		state = in.State
	}
	// Only an accept writes a reason, and it is stored trimmed. Any other
	// transition leaves the operator's existing reason alone.
	var reason *string
	if in.State == "accepted" && in.Reason != nil {
		trimmed := strings.TrimSpace(*in.Reason)
		reason = &trimmed
	}
	if err := s.db(r).UpdateScanFinding(key, state, reason); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "security.finding", key+" "+state, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// syncSecurityFeed refreshes the KEV snapshot on demand. OSV has no bulk sync:
// its answers are fetched per component and cached.
func (s *Server) syncSecurityFeed(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Source string `json:"source"`
	}
	if err := decode(r, &in); err != nil || strings.TrimSpace(in.Source) != scan.KEVSource {
		writeError(w, http.StatusBadRequest, "only the kev snapshot can be synced on demand")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	prev, _ := scan.LoadKEV(s.db(r))
	next, changed, err := scan.NewKEVClient().Refresh(ctx, prev)
	if err != nil {
		_ = s.db(r).RecordVulnFailure(scan.KEVSource, err.Error())
		writeError(w, http.StatusBadGateway, "the KEV snapshot could not be fetched")
		return
	}
	if err := next.Save(s.db(r)); err != nil {
		writeError(w, http.StatusInternalServerError, "the KEV snapshot could not be saved")
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "security.feed", scan.KEVSource, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"source": scan.KEVSource, "changed": changed, "records": next.Len()})
}

func (s *Server) getSecuritySchedule(w http.ResponseWriter, r *http.Request) {
	siteID := s.db(r).SiteID()
	sched, err := s.db(r).ScanSchedule(siteID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if sched == nil {
		sched = &model.ScanSchedule{SiteID: siteID, Cadence: scan.CadenceWeekly, Hour: 3, Enabled: false}
	}
	writeJSON(w, http.StatusOK, map[string]any{"schedule": sched})
}

func (s *Server) putSecuritySchedule(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Cadence  string   `json:"cadence"`
		Hour     int      `json:"hour"`
		Day      int      `json:"day"`
		Enabled  bool     `json:"enabled"`
		Triggers []string `json:"triggers"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	msg := validSecuritySchedule(in.Cadence, in.Hour, in.Day, in.Triggers)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	sess := sessionFrom(r)
	sched := model.ScanSchedule{
		SiteID: s.db(r).SiteID(), Cadence: in.Cadence, Hour: in.Hour, Day: in.Day,
		Enabled: in.Enabled, Triggers: in.Triggers, UpdatedBy: sess.Username,
	}
	if err := s.db(r).SaveScanSchedule(sched); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	s.db(r).AddAudit(sess.Username, "security.schedule", in.Cadence, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"schedule": sched})
}

func validSecuritySchedule(cadence string, hour, day int, triggers []string) string {
	switch cadence {
	case scan.CadenceDaily, scan.CadenceWeekly, scan.CadenceMonthly:
	default:
		return "cadence must be daily, weekly or monthly"
	}
	if hour < 0 || hour > 23 {
		return "hour must be between 0 and 23"
	}
	switch cadence {
	case scan.CadenceWeekly:
		if day < 0 || day > 6 {
			return "day must be a weekday between 0 and 6"
		}
	case scan.CadenceMonthly:
		if day < 1 || day > 28 {
			return "day must be between 1 and 28"
		}
	}
	for _, trigger := range triggers {
		switch trigger {
		case scan.TriggerConfig, scan.TriggerUpgrade, scan.TriggerKEV:
		default:
			return "unknown trigger: " + trigger
		}
	}
	return ""
}

func (s *Server) getSecurityLimits(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"paused": s.securityPaused(r), "probes_per_second": s.securityPerSecond(r),
	})
}

func (s *Server) putSecurityLimits(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Paused    *bool `json:"paused"`
		PerSecond *int  `json:"probes_per_second"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	kv := map[string]string{}
	if in.Paused != nil {
		kv["security_paused"] = b2s(*in.Paused)
	}
	if in.PerSecond != nil {
		if *in.PerSecond < 1 || *in.PerSecond > 50 {
			writeError(w, http.StatusBadRequest, "probes per second must be between 1 and 50")
			return
		}
		kv["security_probes_per_second"] = strconv.Itoa(*in.PerSecond)
	}
	if err := s.db(r).SetSettings(kv); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "security.limits", "updated", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"paused": s.securityPaused(r), "probes_per_second": s.securityPerSecond(r),
	})
}

func (s *Server) securityPaused(r *http.Request) bool {
	return scan.Paused(s.db(r))
}

func (s *Server) securityPerSecond(r *http.Request) int {
	return scan.ProbesPerSecond(s.db(r))
}

func (s *Server) securityDeps(r *http.Request) scan.ExecuteDeps {
	var trust *scantrust.Registry
	if b := s.siteRes(r); b != nil {
		trust = b.ScanTrust
	}
	// A nil *notify.Manager kept in the interface is not a nil interface, so a
	// run that resolved a finding would call a method on nothing.
	var notifier scan.Notifier
	if s.notify != nil {
		notifier = s.notify
	}
	deps := scan.ExecuteDeps{
		Store: s.db(r), Box: s.box, Notify: notifier, Bans: s.bans, Trust: trust,
		PerSecond: s.securityPerSecond(r), ConsoleHost: s.consoleHost(r),
	}
	if s.securityWAN != nil {
		deps.WANBase = s.securityWAN
	} else {
		// The hostname is tried first, so an edge in front of it is still
		// exercised. The listener is only the fallback for a hostname that
		// does not resolve or a port that is unreachable.
		deps.WANFallback = func(string) string { return s.listenerWANBase() }
	}
	return deps
}

// listenerWANBase derives the listener endpoint a scan falls back to from the
// WAN listener the node actually bound. The site hostname is sent as Host and
// TLS SNI, so a hostname that does not resolve here, or a listener that is not
// on 443, does not fail a run whose published hostname is unreachable.
func (s *Server) listenerWANBase() string {
	listen := ""
	if s.cfg != nil {
		listen = s.cfg.ListenWAN
	}
	return scan.ListenerBase(listen)
}

func b2s(v bool) string {
	if v {
		return "1"
	}
	return "0"
}
