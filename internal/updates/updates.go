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
	"net/url"
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
	// ErrAppUpdateUnsupported means this deployment cannot rebuild its own
	// application binary, for example because it runs from a container image.
	ErrAppUpdateUnsupported = errors.New("application self-update is unavailable")
)

// AppRepo is the repository this build updates. It is also the origin a
// checkout recorded from the console must have: the helper rebuilds and installs
// as root, so another repository would be code the operator never approved.
// A fork sets it at build time with -X .../internal/updates.AppRepo=owner/repo.
var AppRepo = "kenhermesagent-lab/WAF-Proxy-Docker"

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

	appMu      sync.Mutex
	app        appInfo
	appExpires time.Time
	appRepo    string
	appAPIBase string
	appRawBase string
	appBusy    atomic.Bool

	// appStatus is the host view the root helper reports. Local paths are
	// meaningless inside a Docker container, so they are only a fallback for a
	// native install whose helper is not running.
	statusMu    sync.Mutex
	appStatus   AppStatus
	appStatusOK bool

	appRunMu     sync.Mutex
	appRunActive bool
	appRunErr    string
	appRunOutput string

	buildMu sync.Mutex
	opMu    sync.Mutex
	busy    atomic.Bool
}

type appInfo struct {
	available     bool
	remoteVersion string
	remoteCommit  string
	remoteDate    string
	remoteURL     string
	remoteBranch  string
	err           string
	checked       bool
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

	AppUpdateAvailable bool   `json:"app_update_available"`
	AppRemoteVersion   string `json:"app_remote_version,omitempty"`
	AppRemoteCommit    string `json:"app_remote_commit,omitempty"`
	AppRemoteDate      string `json:"app_remote_date,omitempty"`
	AppRemoteURL       string `json:"app_remote_url,omitempty"`
	AppRemoteBranch    string `json:"app_remote_branch,omitempty"`
	AppUpdateError     string `json:"app_update_error,omitempty"`
	AppUpdateSupported bool   `json:"app_update_supported"`
	AppUpdateReason    string `json:"app_update_reason,omitempty"`
	AppSourceDir       string `json:"app_source_dir,omitempty"`
	AppUpdating        bool   `json:"app_updating"`
	AppUpdateRunError  string `json:"app_update_run_error,omitempty"`
	AppUpdateOutput    string `json:"app_update_output,omitempty"`
}

// AppUpdateStatus is polled while an application rebuild is running.
type AppUpdateStatus struct {
	Updating bool   `json:"updating"`
	Error    string `json:"error,omitempty"`
	Output   string `json:"output,omitempty"`
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
		appRepo:      AppRepo,
		appAPIBase:   "https://api.github.com",
		appRawBase:   "https://raw.githubusercontent.com",
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
	ready, helperErr := m.helperState()
	return Snapshot{
		Available:    m.host.available,
		Reason:       m.host.reason,
		Platform:     m.host.platform,
		Container:    m.host.container,
		Packages:     []Package{},
		HelperReady:  ready,
		HelperError:  helperErr,
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
	base := m.mergeApp(m.baseSnapshot(), m.appSnapshot(ctx))
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
		return m.mergeApp(out, m.appSnapshot(ctx))
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
	m.refreshAppStatus(ctx)
	snap = m.mergeApp(snap, m.appSnapshot(ctx))
	m.cacheMu.Lock()
	m.cache = snap
	m.expires = m.now().Add(10 * time.Minute)
	m.cacheMu.Unlock()
	return snap
}

func (m *Manager) mergeApp(snap Snapshot, app appInfo) Snapshot {
	snap.AppUpdateAvailable = app.available
	snap.AppRemoteVersion = app.remoteVersion
	snap.AppRemoteCommit = app.remoteCommit
	snap.AppRemoteDate = app.remoteDate
	snap.AppRemoteURL = app.remoteURL
	snap.AppRemoteBranch = app.remoteBranch
	snap.AppUpdateError = app.err
	snap.AppUpdating = m.appBusy.Load()
	m.appRunMu.Lock()
	snap.AppUpdateRunError = m.appRunErr
	snap.AppUpdateOutput = m.appRunOutput
	m.appRunMu.Unlock()
	ready, msg := m.helperState()
	status, fromHelper := m.appStatusSnapshot()
	if fromHelper {
		snap.AppSourceDir = status.SourceDir
	} else {
		// Native install without a running helper, or a test manager: inspect
		// the paths directly, which is correct on the machine that runs the
		// console.
		snap.AppSourceDir = m.AppSourceDir()
		status = AppStatus{
			SourceDir:      snap.AppSourceDir,
			CheckoutExists: dirExists(snap.AppSourceDir),
			MissingScripts: MissingUpdateScripts(),
		}
	}
	docker := m.host.container || status.Mode == "docker"
	switch {
	case m.host.container && !ready:
		snap.AppUpdateSupported = false
		snap.AppUpdateReason = "Docker images cannot rebuild themselves from inside the container. On the host run sudo ./deploy/install-docker-updater.sh once, then use this button."
	case !ready:
		snap.AppUpdateSupported = false
		snap.AppUpdateReason = msg
	case m.appRepo == "":
		snap.AppUpdateSupported = false
		snap.AppUpdateReason = "No application repository is configured for update checks."
	case snap.AppSourceDir == "":
		snap.AppUpdateSupported = false
		snap.AppUpdateReason = "The update helper is running but has no repository directory recorded, so it has nothing to rebuild."
	case !status.CheckoutExists:
		snap.AppUpdateSupported = false
		snap.AppUpdateReason = "The recorded checkout " + snap.AppSourceDir + " no longer exists on this host, so there is nothing to rebuild."
	case len(status.MissingScripts) > 0:
		snap.AppUpdateSupported = false
		installer := "sudo ./deploy/install.sh"
		if docker {
			installer = "sudo ./deploy/install-docker-updater.sh"
		}
		snap.AppUpdateReason = "The installed update scripts are missing (" + strings.Join(status.MissingScripts, ", ") +
			"); re-run " + installer + " from the checkout to restore them."
	default:
		snap.AppUpdateSupported = true
		snap.AppUpdateReason = ""
	}
	return snap
}

// refreshAppStatus asks the root helper whether the recorded checkout and the
// installed updater scripts are present. A Docker install runs the console in a
// container, where /etc/wafproxy and /usr/local/waf-proxy belong to the image,
// not to the host the updater works on.
func (m *Manager) refreshAppStatus(ctx context.Context) {
	status, ok := m.helperAppStatus(ctx)
	m.statusMu.Lock()
	m.appStatus, m.appStatusOK = status, ok
	m.statusMu.Unlock()
}

func (m *Manager) appStatusSnapshot() (AppStatus, bool) {
	m.statusMu.Lock()
	defer m.statusMu.Unlock()
	return m.appStatus, m.appStatusOK
}

func (m *Manager) helperAppStatus(ctx context.Context) (AppStatus, bool) {
	if _, msg := m.helperState(); msg != "" {
		return AppStatus{}, false
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := m.callHelper(ctx, HelperRequest{Action: HelperActionAppStatus})
	if err != nil || !resp.OK {
		return AppStatus{}, false
	}
	return AppStatus{
		SourceDir:      resp.SourceDir,
		Mode:           resp.Mode,
		CheckoutExists: resp.CheckoutExists,
		MissingScripts: resp.MissingScripts,
	}, true
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

// HelperReady reports whether the root helper socket is present.
func (m *Manager) HelperReady() bool {
	if m == nil {
		return false
	}
	ready, _ := m.helperState()
	return ready
}

// HostSupport reports the detected host platform and whether privileged host
// work is possible, so other pages can explain why a feature is unavailable.
func (m *Manager) HostSupport() (platform string, container, available bool, reason string) {
	if m == nil {
		return "", false, false, "The host update manager is not configured."
	}
	return m.host.platform, m.host.container, m.host.available, m.host.reason
}

// RunHelper sends one fixed request to the root helper. The CrowdSec installer
// shares this socket so every privileged action uses the same peer check.
func (m *Manager) RunHelper(ctx context.Context, req HelperRequest) (HelperResponse, error) {
	if m == nil {
		return HelperResponse{}, errors.New("the native update helper is not configured")
	}
	return m.callHelper(ctx, req)
}

func (m *Manager) invalidate() {
	m.cacheMu.Lock()
	m.expires = time.Time{}
	m.cacheMu.Unlock()
	m.appMu.Lock()
	m.appExpires = time.Time{}
	m.appMu.Unlock()
}

// Check refreshes the apt package index through the helper, then rebuilds the
// inventory. It is a privileged operation because apt update needs root.
func (m *Manager) Check(ctx context.Context) (Snapshot, error) {
	m.invalidate()
	if !m.host.available {
		snap := m.Snapshot(ctx)
		snap.Updating = false
		return snap, nil
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

// StartAppUpdate asks the fixed root helper to pull, rebuild and install the
// application from the repository recorded by deploy/install.sh. It accepts no
// URL, branch, command or package from the request. The rebuild runs in the
// background so the browser can keep polling even when a Docker rebuild
// recreates the container running this process.
func (m *Manager) StartAppUpdate(onSuccess func()) error {
	if ready, msg := m.helperState(); !ready {
		return fmt.Errorf("%w: %s", ErrAppUpdateUnsupported, msg)
	}
	m.appRunMu.Lock()
	if m.appRunActive {
		m.appRunMu.Unlock()
		return errors.New("an application update is already running")
	}
	m.appRunActive = true
	m.appRunErr = ""
	m.appRunOutput = ""
	m.appRunMu.Unlock()
	m.appBusy.Store(true)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
		defer cancel()
		resp, err := m.callHelper(ctx, HelperRequest{Action: HelperActionAppUpdate})
		message := ""
		if err != nil {
			message = err.Error()
		} else if !resp.OK {
			message = resp.Error
		}
		m.appRunMu.Lock()
		m.appRunActive = false
		m.appRunErr = message
		m.appRunOutput = tailText(resp.Output, 4000)
		m.appRunMu.Unlock()
		m.appBusy.Store(false)
		m.invalidate()
		if message == "" && onSuccess != nil {
			onSuccess()
		}
	}()
	return nil
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// AppSourceDir returns the checkout recorded for the root helper, or "" when
// install.sh did not record one.
func (m *Manager) AppSourceDir() string {
	if m == nil {
		return ""
	}
	values, err := ReadSelfUpdateConf(SelfUpdateConfFile())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(values["WAFPROXY_UPDATE_SOURCE_DIR"])
}

// ConfigureApp asks the root helper to record a checkout and copy its fixed
// update scripts. The helper validates the directory itself; the browser never
// picks a command, only a path.
func (m *Manager) ConfigureApp(ctx context.Context, dir string) error {
	if m == nil {
		return ErrAppUpdateUnsupported
	}
	if ready, msg := m.helperState(); !ready {
		return errors.New(msg)
	}
	resp, err := m.callHelper(ctx, HelperRequest{Action: HelperActionAppConfigure, Path: dir})
	if err != nil {
		return err
	}
	if !resp.OK {
		if resp.Error != "" {
			return errors.New(resp.Error)
		}
		return errors.New("the update helper rejected the repository directory")
	}
	m.invalidate()
	return nil
}

// AppUpdateStatus reports the background rebuild without hitting the network.
func (m *Manager) AppUpdateStatus() AppUpdateStatus {
	m.appRunMu.Lock()
	defer m.appRunMu.Unlock()
	return AppUpdateStatus{Updating: m.appRunActive, Error: m.appRunErr, Output: m.appRunOutput}
}

func tailText(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
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

// ---------- application repository check ----------

func (m *Manager) appSnapshot(ctx context.Context) appInfo {
	if m.appRepo == "" {
		return appInfo{}
	}
	m.appMu.Lock()
	if m.app.checked && m.now().Before(m.appExpires) {
		out := m.app
		m.appMu.Unlock()
		return out
	}
	m.appMu.Unlock()

	info := m.checkApp(ctx)
	m.appMu.Lock()
	m.app = info
	m.app.checked = true
	wait := 10 * time.Minute
	if info.err != "" {
		wait = 5 * time.Minute
	}
	m.appExpires = m.now().Add(wait)
	m.appMu.Unlock()
	return info
}

func (m *Manager) checkApp(ctx context.Context) appInfo {
	if info, ok := m.checkAppWithHelper(ctx); ok {
		return info
	}
	var info appInfo
	client := m.client
	if client == nil {
		client = &http.Client{Timeout: 12 * time.Second}
	}
	apiBase := strings.TrimRight(m.appAPIBase, "/")
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	commitURL := fmt.Sprintf("%s/repos/%s/commits/main", apiBase, m.appRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, commitURL, nil)
	if err != nil {
		info.err = err.Error()
		return info
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "wafproxy-update-check/1.0")
	resp, err := client.Do(req)
	if err != nil {
		info.err = "repository check failed: " + err.Error()
		return info
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		info.err = fmt.Sprintf("repository check returned HTTP %d", resp.StatusCode)
		if resp.StatusCode == http.StatusNotFound {
			info.err = "repository not found on GitHub; check the repository name, or install the update helper for a private fork"
		}
		return info
	}
	var commit struct {
		SHA     string `json:"sha"`
		HTMLURL string `json:"html_url"`
		Commit  struct {
			Committer struct {
				Date string `json:"date"`
			} `json:"committer"`
		} `json:"commit"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&commit); err != nil {
		info.err = "decode repository response: " + err.Error()
		return info
	}
	info.remoteCommit = strings.TrimSpace(commit.SHA)
	info.remoteDate = strings.TrimSpace(commit.Commit.Committer.Date)
	info.remoteURL = strings.TrimSpace(commit.HTMLURL)
	info.remoteBranch = "main"

	rawBase := strings.TrimRight(m.appRawBase, "/")
	if rawBase == "" {
		rawBase = "https://raw.githubusercontent.com"
	}
	versionURL := fmt.Sprintf("%s/%s/main/VERSION", rawBase, m.appRepo)
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, versionURL, nil); err == nil {
		req.Header.Set("User-Agent", "wafproxy-update-check/1.0")
		if vresp, err := client.Do(req); err == nil {
			defer vresp.Body.Close()
			if vresp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(vresp.Body, 4096))
				info.remoteVersion = strings.TrimSpace(string(body))
			}
		}
	}

	if info.remoteVersion == "" && info.remoteCommit == "" {
		info.err = "repository check returned no version or commit"
		return info
	}
	return m.appAvailability(info)
}

// checkAppWithHelper asks the fixed root helper to fetch the recorded checkout.
// Public repositories fetch anonymously; a private fork uses the checkout
// owner's existing git credentials. The public GitHub API is the fallback when
// no helper is installed.
func (m *Manager) checkAppWithHelper(ctx context.Context) (appInfo, bool) {
	if ready, _ := m.helperState(); !ready {
		return appInfo{}, false
	}
	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := m.callHelper(checkCtx, HelperRequest{Action: HelperActionAppCheck})
	if err != nil || !resp.OK {
		return appInfo{}, false
	}
	line := strings.TrimSpace(resp.Output)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	parts := strings.Split(line, "\t")
	if len(parts) < 3 || strings.TrimSpace(parts[0]) == "" {
		return appInfo{}, false
	}
	info := appInfo{
		remoteCommit:  strings.TrimSpace(parts[0]),
		remoteVersion: strings.TrimSpace(parts[1]),
		remoteDate:    strings.TrimSpace(parts[2]),
	}
	if len(parts) > 3 {
		info.remoteURL = redactRemoteURL(parts[3])
	}
	if len(parts) > 4 {
		info.remoteBranch = strings.TrimSpace(parts[4])
	}
	return m.appAvailability(info), true
}

func (m *Manager) appAvailability(info appInfo) appInfo {
	localCommit := strings.TrimSpace(version.Commit)
	commitKnown := localCommit != "" && localCommit != "dev" && localCommit != "unknown"
	if info.remoteVersion == "" && !commitKnown {
		info.err = "remote VERSION is unavailable and this build has no commit stamp"
	}
	cmp := 0
	if info.remoteVersion != "" && version.Version != "" {
		cmp = compareVersions(info.remoteVersion, version.Version)
	}
	switch {
	case cmp > 0:
		info.available = true
	case cmp < 0:
		info.available = false
	case commitKnown && info.remoteCommit != "" && !sameCommit(localCommit, info.remoteCommit):
		info.available = true
	}
	return info
}

// redactRemoteURL keeps a repository link useful without exposing credentials
// that an operator may have embedded in remote.origin.url.
func redactRemoteURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	u.User = nil
	return u.String()
}

func sameCommit(local, remote string) bool {
	return strings.HasPrefix(remote, local) || strings.HasPrefix(local, remote)
}

// compareVersions compares dotted semantic versions, treating a release as
// newer than a pre-release with the same numeric core.
func compareVersions(a, b string) int {
	core := func(v string) ([]int, string) {
		v = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "v"))
		suffix := ""
		if i := strings.IndexAny(v, "-+"); i >= 0 {
			suffix = v[i:]
			v = v[:i]
		}
		parts := strings.Split(v, ".")
		nums := make([]int, 0, len(parts))
		for _, p := range parts {
			n := 0
			for _, r := range p {
				if r < '0' || r > '9' {
					break
				}
				n = n*10 + int(r-'0')
			}
			nums = append(nums, n)
		}
		return nums, suffix
	}
	an, as := core(a)
	bn, bs := core(b)
	for i := 0; i < len(an) || i < len(bn); i++ {
		av, bv := 0, 0
		if i < len(an) {
			av = an[i]
		}
		if i < len(bn) {
			bv = bn[i]
		}
		if av > bv {
			return 1
		}
		if av < bv {
			return -1
		}
	}
	switch {
	case as == bs:
		return 0
	case as == "":
		return 1
	case bs == "":
		return -1
	case as > bs:
		return 1
	default:
		return -1
	}
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
