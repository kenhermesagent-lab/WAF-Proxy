// Package updates inventories the host packages used by the native service,
// checks the distribution package index, and asks a root-owned helper to apply
// one explicitly managed package upgrade.
package updates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/version"
)

var (
	// ErrUnavailable means this deployment cannot manage host packages, for
	// example because it is running in a container.
	ErrUnavailable = errors.New("host package updates are unavailable")
	// ErrNotManaged means the requested package is not in the embedded allowlist.
	ErrNotManaged = errors.New("package is not managed by WAF-Proxy")
)

type runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Manager owns the update inventory and the short-lived in-memory cache.
type Manager struct {
	log          *slog.Logger
	host         hostInfo
	helperSocket string
	osvBase      string
	client       *http.Client
	run          runner
	now          func() time.Time

	cacheMu sync.Mutex
	cache   Snapshot
	expires time.Time

	buildMu sync.Mutex
	opMu    sync.Mutex
	busy    atomic.Bool
}

type hostInfo struct {
	available bool
	reason    string
	platform  string
	ecosystem string
	container bool
}

// Snapshot is the complete data rendered by the Updates page.
type Snapshot struct {
	Available     bool      `json:"available"`
	Reason        string    `json:"reason,omitempty"`
	Platform      string    `json:"platform,omitempty"`
	Container     bool      `json:"container"`
	CheckedAt     string    `json:"checked_at,omitempty"`
	Packages      []Package `json:"packages"`
	AdvisoryError string    `json:"advisory_error,omitempty"`
	HelperReady   bool      `json:"helper_ready"`
	HelperError   string    `json:"helper_error,omitempty"`
	Updating      bool      `json:"updating"`
	AppVersion    string    `json:"app_version"`
	AppCommit     string    `json:"app_commit"`
	AppBuildDate  string    `json:"app_build_date"`
	GoVersion     string    `json:"go_version"`
}

// Package is one managed host package.
type Package struct {
	Name       string     `json:"name"`
	Role       string     `json:"role,omitempty"`
	Current    string     `json:"current,omitempty"`
	Candidate  string     `json:"candidate,omitempty"`
	Status     string     `json:"status"`
	Severity   string     `json:"severity,omitempty"`
	Security   bool       `json:"security"`
	Advisories []Advisory `json:"advisories,omitempty"`
	CanUpdate  bool       `json:"can_update"`
	Note       string     `json:"note,omitempty"`
}

// Advisory is a high or critical vulnerability that affects the installed
// version according to OSV.
type Advisory struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Score    string `json:"score,omitempty"`
	Summary  string `json:"summary"`
}

// ApplyResult is returned after one helper upgrade completes.
type ApplyResult struct {
	Snapshot Snapshot `json:"snapshot"`
	Output   string   `json:"output,omitempty"`
}

// New creates the manager. Host capabilities are resolved once at process
// start; changing the package manager requires a restart.
func New(log *slog.Logger) *Manager {
	m := &Manager{
		log:          log,
		host:         detectHost(),
		helperSocket: HelperSocketPath(),
		osvBase:      "https://api.osv.dev",
		client:       &http.Client{Timeout: 12 * time.Second},
		run:          execRunner,
		now:          time.Now,
	}
	if !m.host.available {
		log.Warn("host package updates unavailable", "reason", m.host.reason)
	}
	return m
}

func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	return cmd.CombinedOutput()
}

func detectHost() hostInfo {
	if inContainer() {
		return hostInfo{
			container: true,
			reason:    "Host package updates are unavailable inside a container. Rebuild or pull a newer WAF-Proxy image instead.",
		}
	}
	id, versionID, pretty := readOSRelease()
	id = strings.ToLower(strings.TrimSpace(id))
	versionID = strings.TrimSpace(versionID)
	platform := strings.TrimSpace(pretty)
	if platform == "" {
		platform = strings.TrimSpace(id + " " + versionID)
	}
	ecosystem := ""
	switch id {
	case "debian":
		ecosystem = "Debian"
	case "ubuntu":
		ecosystem = "Ubuntu"
	default:
		return hostInfo{platform: platform, reason: "Host package updates currently require Debian or Ubuntu with apt."}
	}
	if versionID != "" {
		ecosystem += ":" + versionID
	}
	for _, bin := range []string{"apt-get", "apt-cache", "dpkg-query", "dpkg"} {
		if _, err := exec.LookPath(bin); err != nil {
			return hostInfo{platform: platform, reason: "Host package updates need " + bin + " from the distribution package manager."}
		}
	}
	return hostInfo{available: true, platform: platform, ecosystem: ecosystem}
}

func inContainer() bool {
	for _, path := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	s := strings.ToLower(string(data))
	return strings.Contains(s, "docker") || strings.Contains(s, "kubepods") ||
		strings.Contains(s, "containerd") || strings.Contains(s, "lxc")
}

func readOSRelease() (id, versionID, pretty string) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch key {
		case "ID":
			id = value
		case "VERSION_ID":
			versionID = value
		case "PRETTY_NAME":
			pretty = value
		}
	}
	return
}

func (m *Manager) baseSnapshot() Snapshot {
	return Snapshot{
		Available:    m.host.available,
		Reason:       m.host.reason,
		Platform:     m.host.platform,
		Container:    m.host.container,
		Packages:     []Package{},
		Updating:     m.busy.Load(),
		AppVersion:   version.Version,
		AppCommit:    version.Commit,
		AppBuildDate: version.BuildDate,
		GoVersion:    runtime.Version(),
	}
}

// Snapshot returns the cached inventory, refreshing it after the short cache
// expires. Package names and versions are sent to OSV for advisory matching;
// no host data or credentials are sent.
func (m *Manager) Snapshot(ctx context.Context) Snapshot {
	base := m.baseSnapshot()
	if !m.host.available {
		return base
	}
	m.buildMu.Lock()
	defer m.buildMu.Unlock()
	m.cacheMu.Lock()
	if !m.expires.IsZero() && m.now().Before(m.expires) {
		out := m.cache
		m.cacheMu.Unlock()
		out.Updating = m.busy.Load()
		return out
	}
	m.cacheMu.Unlock()

	snap, err := m.build(ctx)
	if err != nil {
		base.Available = false
		base.Reason = err.Error()
		return base
	}
	snap.Available = true
	snap.CheckedAt = m.now().UTC().Format(time.RFC3339)
	snap.HelperReady, snap.HelperError = m.helperState()
	snap.Updating = m.busy.Load()
	m.cacheMu.Lock()
	m.cache = snap
	m.expires = m.now().Add(10 * time.Minute)
	m.cacheMu.Unlock()
	return snap
}

func (m *Manager) build(ctx context.Context) (Snapshot, error) {
	snap := m.baseSnapshot()
	installed, err := m.installedVersions(ctx)
	if err != nil {
		return snap, err
	}
	snap.AdvisoryError = ""
	for _, entry := range Catalog() {
		p := Package{Name: entry.Name, Role: entry.Role, Status: "unknown"}
		p.Current = installed[entry.Name]
		if p.Current == "" {
			p.Status = "missing"
			p.Note = "Not installed on this host."
			snap.Packages = append(snap.Packages, p)
			continue
		}
		candidate, securityRepo, policyErr := m.candidateVersion(ctx, entry.Name)
		p.Candidate = candidate
		if policyErr != nil || candidate == "" {
			p.Status = "unknown"
			p.Note = "The package index has no candidate version."
			if policyErr != nil {
				p.Note = policyErr.Error()
			}
		} else if !m.newer(ctx, p.Current, candidate) {
			p.Status = "current"
		} else if securityRepo {
			p.Status = "security"
			p.Security = true
			p.Severity = "unknown"
		} else {
			p.Status = "update"
		}

		advisories, advErr := m.advisories(ctx, entry.Name, p.Current)
		if advErr != nil {
			if snap.AdvisoryError == "" {
				snap.AdvisoryError = advErr.Error()
			}
		} else if len(advisories) > 0 {
			p.Advisories = advisories
			p.Severity = advisories[0].Severity
			p.Security = true
			if p.Candidate != "" && m.newer(ctx, p.Current, p.Candidate) {
				p.Status = "security"
			} else {
				p.Status = "vulnerable"
				p.Note = "No newer package is published in the configured package index."
			}
		}
		p.CanUpdate = p.Candidate != "" && m.newer(ctx, p.Current, p.Candidate)
		if p.CanUpdate {
			ready, _ := m.helperState()
			if !ready {
				p.CanUpdate = false
				p.Note = "The native update helper is not installed or not running."
			}
		}
		snap.Packages = append(snap.Packages, p)
	}
	sort.SliceStable(snap.Packages, func(i, j int) bool {
		return severityRank(snap.Packages[i].Severity) > severityRank(snap.Packages[j].Severity)
	})
	return snap, nil
}

func (m *Manager) installedVersions(ctx context.Context) (map[string]string, error) {
	entries := Catalog()
	if len(entries) == 0 {
		return map[string]string{}, nil
	}
	args := []string{"-W", "-f=${Package}\t${Version}\n", "--"}
	for _, e := range entries {
		args = append(args, e.Name)
	}
	out, err := m.run(ctx, "dpkg-query", args...)
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("read installed package versions: %w", err)
	}
	versions := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		name, version, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if ok && validPackageName(name) && version != "" {
			versions[name] = version
		}
	}
	return versions, nil
}

func (m *Manager) candidateVersion(ctx context.Context, name string) (string, bool, error) {
	out, err := m.run(ctx, "apt-cache", "policy", name)
	if err != nil {
		return "", false, fmt.Errorf("read package policy: %w", err)
	}
	candidate, security := parseAptPolicy(string(out))
	if candidate == "" {
		return "", false, nil
	}
	return candidate, security, nil
}

func (m *Manager) newer(ctx context.Context, current, candidate string) bool {
	if current == "" || candidate == "" || current == candidate {
		return false
	}
	_, err := m.run(ctx, "dpkg", "--compare-versions", current, "lt", candidate)
	if err == nil {
		return true
	}
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
		return false
	}
	return false
}

func parseAptPolicy(out string) (candidate string, security bool) {
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Candidate:"); ok {
			candidate = strings.TrimSpace(v)
			if candidate == "(none)" {
				candidate = ""
			}
			break
		}
	}
	if candidate == "" {
		return "", false
	}
	inTable := false
	current := ""
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "Version table:") {
			inTable = true
			continue
		}
		if !inTable || trim == "" {
			continue
		}
		fields := strings.Fields(trim)
		if len(fields) >= 2 && isDigits(fields[len(fields)-1]) {
			// A version row is either "1.2.3 500" or "*** 1.2.3 100".
			version := fields[0]
			if version == "***" && len(fields) >= 3 {
				version = fields[1]
			}
			current = version
			continue
		}
		if current == candidate && strings.Contains(strings.ToLower(trim), "security") {
			security = true
		}
	}
	return candidate, security
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func (m *Manager) helperState() (bool, string) {
	info, err := os.Stat(m.helperSocket)
	if err != nil {
		return false, "The native update helper is not installed or is not running."
	}
	if info.Mode()&os.ModeSocket == 0 {
		return false, "The update helper socket is not a Unix socket."
	}
	return true, ""
}

func (m *Manager) invalidate() {
	m.cacheMu.Lock()
	m.expires = time.Time{}
	m.cacheMu.Unlock()
}

// Check refreshes the apt package index through the helper, then rebuilds the
// inventory. It is a privileged operation because apt update needs root.
func (m *Manager) Check(ctx context.Context) (Snapshot, error) {
	if !m.host.available {
		return m.baseSnapshot(), ErrUnavailable
	}
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.busy.Store(true)
	defer m.busy.Store(false)
	resp, err := m.callHelper(ctx, HelperRequest{Action: HelperActionCheck})
	if err != nil {
		return m.baseSnapshot(), fmt.Errorf("check for updates: %w", err)
	}
	if !resp.OK {
		return m.baseSnapshot(), fmt.Errorf("check for updates: %s", resp.Error)
	}
	m.invalidate()
	snap := m.Snapshot(ctx)
	snap.Updating = false
	return snap, nil
}

// Apply asks the helper to upgrade exactly one package from the embedded
// allowlist. It never accepts a package name from the request without checking
// the catalog here as well.
func (m *Manager) Apply(ctx context.Context, name string) (ApplyResult, error) {
	if !m.host.available {
		return ApplyResult{Snapshot: m.baseSnapshot()}, ErrUnavailable
	}
	if !managed(name) {
		return ApplyResult{Snapshot: m.baseSnapshot()}, ErrNotManaged
	}
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.busy.Store(true)
	defer m.busy.Store(false)
	resp, err := m.callHelper(ctx, HelperRequest{Action: HelperActionApply, Package: name})
	if err != nil {
		return ApplyResult{Snapshot: m.baseSnapshot()}, fmt.Errorf("update %s: %w", name, err)
	}
	if !resp.OK {
		return ApplyResult{Snapshot: m.baseSnapshot(), Output: resp.Output}, fmt.Errorf("update %s: %s", name, resp.Error)
	}
	m.invalidate()
	snap := m.Snapshot(ctx)
	snap.Updating = false
	return ApplyResult{Snapshot: snap, Output: resp.Output}, nil
}

func managed(name string) bool {
	for _, e := range Catalog() {
		if e.Name == name {
			return true
		}
	}
	return false
}

func (m *Manager) callHelper(ctx context.Context, req HelperRequest) (HelperResponse, error) {
	if _, msg := m.helperState(); msg != "" {
		return HelperResponse{}, errors.New(msg)
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", m.helperSocket)
	if err != nil {
		return HelperResponse{}, fmt.Errorf("connect to update helper: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(2 * time.Minute)
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return HelperResponse{}, fmt.Errorf("send helper request: %w", err)
	}
	var resp HelperResponse
	if err := json.NewDecoder(io.LimitReader(conn, 64<<10)).Decode(&resp); err != nil {
		return HelperResponse{}, fmt.Errorf("read helper response: %w", err)
	}
	return resp, nil
}

// ---------- OSV advisories ----------

type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID                string         `json:"id"`
	Summary           string         `json:"summary"`
	Details           string         `json:"details"`
	Severity          []osvSeverity  `json:"severity"`
	DatabaseSpecific  map[string]any `json:"database_specific"`
	EcosystemSpecific map[string]any `json:"ecosystem_specific"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

func (m *Manager) advisories(ctx context.Context, name, installed string) ([]Advisory, error) {
	if m.host.ecosystem == "" {
		return nil, nil
	}
	body, err := json.Marshal(map[string]any{
		"package": map[string]string{"name": name, "ecosystem": m.host.ecosystem},
		"version": installed,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(m.osvBase, "/")+"/v1/query", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("security advisory lookup: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("security advisory lookup returned HTTP %d", resp.StatusCode)
	}
	var parsed osvResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode security advisories: %w", err)
	}
	out := []Advisory{}
	seen := map[string]bool{}
	for _, v := range parsed.Vulns {
		adv, ok := advisoryFrom(v)
		if !ok || seen[adv.ID] {
			continue
		}
		seen[adv.ID] = true
		out = append(out, adv)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if severityRank(out[i].Severity) != severityRank(out[j].Severity) {
			return severityRank(out[i].Severity) > severityRank(out[j].Severity)
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > 8 {
		out = out[:8]
	}
	return out, nil
}

func advisoryFrom(v osvVuln) (Advisory, bool) {
	sev, score := highestSeverity(v)
	if sev != "critical" && sev != "high" {
		return Advisory{}, false
	}
	id := strings.TrimSpace(v.ID)
	if id == "" {
		return Advisory{}, false
	}
	summary := strings.TrimSpace(v.Summary)
	if summary == "" {
		summary = strings.TrimSpace(v.Details)
	}
	summary = strings.Join(strings.Fields(summary), " ")
	if len(summary) > 260 {
		summary = strings.TrimSpace(summary[:260]) + "…"
	}
	if summary == "" {
		summary = "Security advisory"
	}
	return Advisory{ID: id, Severity: sev, Score: score, Summary: summary}, true
}

func highestSeverity(v osvVuln) (string, string) {
	best, bestScore := "", ""
	for _, s := range v.Severity {
		sev, score := "", ""
		switch strings.ToUpper(s.Type) {
		case "CVSS_V3":
			if n, ok := CVSSv3Score(s.Score); ok {
				sev = severityForScore(n)
				score = strconv.FormatFloat(n, 'f', 1, 64)
			}
		case "UBUNTU":
			sev = normalizeSeverity(s.Score)
		}
		if severityRank(sev) > severityRank(best) {
			best, bestScore = sev, score
		}
	}
	if best != "" {
		return best, bestScore
	}
	for _, src := range []map[string]any{v.DatabaseSpecific, v.EcosystemSpecific} {
		for _, key := range []string{"severity", "urgency"} {
			if raw, ok := src[key].(string); ok {
				if sev := normalizeSeverity(raw); severityRank(sev) > severityRank(best) {
					best = sev
				}
			}
		}
	}
	return best, bestScore
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low", "negligible", "unimportant":
		return "low"
	default:
		return ""
	}
}

func severityForScore(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// CatalogNames exposes the allowlist to the root helper without duplicating it.
func CatalogNames() []string {
	out := make([]string, 0, len(Catalog()))
	for _, e := range Catalog() {
		out = append(out, e.Name)
	}
	return out
}

// SocketDir is used by the installer and helper tests.
func SocketDir(path string) string { return filepath.Dir(path) }
