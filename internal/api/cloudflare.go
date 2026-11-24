package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	cf "github.com/kenhermesagent-lab/waf-proxy-docker/internal/cloudflared"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// cfLookPath is injectable so a test can describe a host without the binary.
var cfLookPath = exec.LookPath

// Cloudflare edge ranges, used to tell a proxied hostname from one that also
// answers from this host directly.
var cloudflareRanges = func() []netip.Prefix {
	raw := []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
		"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
		"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
		"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
	}
	out := make([]netip.Prefix, 0, len(raw))
	for _, p := range raw {
		if prefix, err := netip.ParsePrefix(p); err == nil {
			out = append(out, prefix)
		}
	}
	return out
}()

type cloudflareView struct {
	Enabled          bool              `json:"enabled"`
	Installed        bool              `json:"installed"`
	Version          string            `json:"version"`
	State            string            `json:"state"`
	Connections      int               `json:"connections"`
	Error            string            `json:"error,omitempty"`
	TokenSet         bool              `json:"token_set"`
	TokenTail        string            `json:"token_tail,omitempty"`
	TunnelID         string            `json:"tunnel_id"`
	StrictOrigin     bool              `json:"strict_origin"`
	MetricsAddr      string            `json:"metrics_addr"`
	Container        bool              `json:"container"`
	HelperReady      bool              `json:"helper_ready"`
	InstallSupported bool              `json:"install_supported"`
	InstallReason    string            `json:"install_reason,omitempty"`
	InstallRunning   bool              `json:"install_running"`
	InstallOutput    string            `json:"install_output,omitempty"`
	InstallError     string            `json:"install_error,omitempty"`
	ConsoleHost      string            `json:"console_host"`
	GUIPort          int               `json:"gui_port"`
	GUITLS           bool              `json:"gui_tls"`
	RestartRequired  bool              `json:"restart_required"`
	Log              []string          `json:"log"`
	Checks           []cloudflareCheck `json:"checks"`
	ChecksAt         string            `json:"checks_at,omitempty"`
}

type cloudflareCheck struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type cloudflareRequest struct {
	Enabled      *bool   `json:"enabled"`
	Token        *string `json:"token"`
	TunnelID     *string `json:"tunnel_id"`
	StrictOrigin *bool   `json:"strict_origin"`
}

// SetCloudflared attaches the connector supervisor main starts at boot.
func (s *Server) SetCloudflared(sup *cf.Supervisor) { s.cloudflared = sup }

func (s *Server) setCloudflareNonce(nonce string) {
	if nonce != "" {
		s.cfNonce.Store(nonce)
	}
}

func (s *Server) getCloudflare(w http.ResponseWriter, r *http.Request) {
	// The tunnel belongs to the host, not to a site: one connector serves every
	// hostname, so the settings stay in the unscoped store.
	kv, err := s.st.Settings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	cfg := cf.Load(kv, s.box)
	view := s.cloudflareViewFor(r, kv, cfg)
	s.cfMu.Lock()
	view.Checks, view.ChecksAt = s.cfChecks, s.cfChecked
	s.cfMu.Unlock()
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) cloudflareViewFor(r *http.Request, kv map[string]string, cfg cf.Settings) cloudflareView {
	snap := cf.Snapshot{}
	if s.cloudflared != nil {
		snap = s.cloudflared.Snapshot()
	}
	installed := snap.Installed
	if s.cloudflared == nil {
		_, err := cfLookPath("cloudflared")
		installed = err == nil
	}
	view := cloudflareView{
		Enabled:         cfg.Enabled,
		MetricsAddr:     cf.DefaultMetricsAddr,
		Installed:       installed,
		Version:         snap.Version,
		State:           string(snap.State),
		Connections:     snap.Connections,
		Error:           snap.Error,
		TokenSet:        cfg.Token != "",
		TunnelID:        cfg.TunnelID,
		StrictOrigin:    cfg.StrictOrigin,
		Container:       s.cloudflareContainer(),
		HelperReady:     s.updates != nil && s.updates.HelperReady(),
		ConsoleHost:     s.consoleHost(r),
		GUIPort:         settingPort(kv["gui_port"], listenPort(s.cfg.ListenGUI, 8443)),
		GUITLS:          s.cfg.ListenGUITLS,
		RestartRequired: snap.RestartRequired,
		Log:             snap.Log,
	}
	if s.cloudflared == nil {
		view.State = string(cf.StateStopped)
	} else {
		view.MetricsAddr = s.cloudflared.MetricsAddr()
	}
	if view.State == "" {
		view.State = string(cf.StateStopped)
	}
	if view.Log == nil {
		view.Log = []string{}
	}
	if cfg.Token != "" {
		tail := cfg.Token
		if len(tail) > 4 {
			tail = tail[len(tail)-4:]
		}
		view.TokenTail = tail
	}
	supported, reason := s.cloudflareInstallSupport(view.Container)
	view.InstallSupported, view.InstallReason = supported, reason
	s.cfMu.Lock()
	view.InstallRunning, view.InstallError, view.InstallOutput = s.cfRunning, s.cfErr, s.cfOutput
	s.cfMu.Unlock()
	return view
}

type cloudflareInstall struct {
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
	Container bool   `json:"container"`
	Running   bool   `json:"running"`
	Error     string `json:"error,omitempty"`
	Output    string `json:"output,omitempty"`
}

func (s *Server) cloudflaredInstallStatus() cloudflareInstall {
	container := s.cloudflareContainer()
	st := cloudflareInstall{Container: container}
	if _, err := cfLookPath("cloudflared"); err == nil {
		st.Installed = true
		if s.cloudflared != nil {
			st.Version = s.cloudflared.Snapshot().Version
		}
	}
	supported, reason := s.cloudflareInstallSupport(container)
	st.Supported, st.Reason = supported, reason
	s.cfMu.Lock()
	st.Running, st.Error, st.Output = s.cfRunning, s.cfErr, s.cfOutput
	s.cfMu.Unlock()
	return st
}

// cloudflareInstallSupport mirrors the CrowdSec card: a container cannot install
// host packages, and a host without the root helper stays read-only.
func (s *Server) cloudflareInstallSupport(container bool) (bool, string) {
	switch {
	case container:
		return false, "This console runs in a container, so it cannot install host packages. Install the connector next to the container; the tunnel does not need to run inside it."
	case s.updates == nil:
		return false, "The host update manager is not configured."
	case !s.updates.HelperReady():
		return false, "The privileged host helper is not installed. Re-run sudo ./deploy/install.sh, then reload this page."
	}
	return true, ""
}

func (s *Server) cloudflareContainer() bool {
	if s.updates == nil {
		return false
	}
	_, container, _, _ := s.updates.HostSupport()
	return container
}

// consoleHost is the hostname this console was published on. The site record
// wins; a single-site install that never set one uses the request's host.
// listenPort is the fallback for the console port when the setting is empty,
// so a page never sends the operator to a port the process does not use.
func listenPort(addr string, fallback int) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fallback
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fallback
	}
	return n
}

func (s *Server) consoleHost(r *http.Request) string {
	st := s.db(r)
	if site, err := st.SiteByID(st.SiteID()); err == nil && site != nil && site.ConsoleHost != "" {
		return site.ConsoleHost
	}
	return store.NormalizeHost(r.Host)
}

// requireHostConsole refuses a host-wide write from a tenant console.
func (s *Server) requireHostConsole(w http.ResponseWriter, r *http.Request, feature string) bool {
	if s.consoleSite(r) != s.st.SiteID() {
		writeError(w, http.StatusForbidden, feature+" is host-wide; change it from the host console")
		return false
	}
	return true
}

func (s *Server) putCloudflare(w http.ResponseWriter, r *http.Request) {
	if !s.requireHostConsole(w, r, "the tunnel connector") {
		return
	}
	var req cloudflareRequest
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	kv, err := s.st.Settings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	cfg := cf.Load(kv, s.box)
	before := cfg
	if req.Enabled != nil {
		cfg.Enabled = *req.Enabled
	}
	if req.Token != nil {
		token := strings.TrimSpace(*req.Token)
		if token == "" {
			cfg.ClearToken = true
			cfg.Token = ""
		} else if !validTunnelToken(token) {
			writeError(w, http.StatusBadRequest, "that does not look like a tunnel token: copy the full token from the Cloudflare dashboard")
			return
		} else {
			cfg.Token = token
		}
	}
	if req.TunnelID != nil {
		id := strings.TrimSpace(*req.TunnelID)
		if id != "" && !validTunnelID(id) {
			writeError(w, http.StatusBadRequest, "the tunnel ID is a UUID from the Cloudflare dashboard")
			return
		}
		cfg.TunnelID = id
	}
	if req.StrictOrigin != nil {
		cfg.StrictOrigin = *req.StrictOrigin
	}
	if cfg.Enabled && cfg.Token == "" {
		writeError(w, http.StatusBadRequest, "paste the tunnel token before enabling the connector")
		return
	}
	if cfg.Nonce == "" {
		if cfg.Nonce, err = wfcrypto.RandomToken(16); err != nil {
			writeError(w, http.StatusInternalServerError, "cannot generate the check nonce")
			return
		}
	}
	next, err := cf.Apply(s.box, cfg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot seal the tunnel token")
		return
	}
	if err := s.st.SetSettings(next); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot save settings")
		return
	}
	s.applyCloudflare(before, cfg)
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "cloudflare.update", cloudflareAudit(cfg, before), clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func cloudflareAudit(next, before cf.Settings) string {
	var parts []string
	if next.Enabled != before.Enabled {
		parts = append(parts, fmt.Sprintf("connector %s", onOff(next.Enabled)))
	}
	if next.Token != before.Token || next.ClearToken {
		parts = append(parts, "tunnel token replaced")
	}
	if next.TunnelID != before.TunnelID {
		parts = append(parts, "tunnel ID changed")
	}
	if next.StrictOrigin != before.StrictOrigin {
		parts = append(parts, fmt.Sprintf("strict origin %s", onOff(next.StrictOrigin)))
	}
	if len(parts) == 0 {
		return "cloudflare settings saved"
	}
	return strings.Join(parts, ", ")
}

func onOff(v bool) string {
	if v {
		return "enabled"
	}
	return "disabled"
}

// applyCloudflare starts, stops or replaces the connector and flips the client
// IP trust, so saved settings take effect without a process restart.
func (s *Server) applyCloudflare(before, after cf.Settings) {
	if s.cloudflared != nil {
		switch {
		case !after.Enabled || after.Token == "":
			s.cloudflared.Stop()
		case after.Token != before.Token:
			if err := s.cloudflared.Restart(after.Token); err != nil {
				s.log.Warn("cloudflared connector would not start", "err", err)
			}
		case s.cloudflared.Snapshot().State != cf.StateRunning:
			if err := s.cloudflared.Start(after.Token); err != nil {
				s.log.Warn("cloudflared connector would not start", "err", err)
			}
		}
	}
	trustedProxies.SetCDN(after.Enabled && after.StrictOrigin)
	s.setCloudflareNonce(after.Nonce)
}

func validTunnelToken(token string) bool {
	if len(token) < 20 || len(token) > 4096 {
		return false
	}
	for _, c := range token {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '+', c == '/', c == '=', c == '.':
		default:
			return false
		}
	}
	return true
}

func validTunnelID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func (s *Server) cloudflareConnector(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action string `json:"action"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	kv, err := s.st.Settings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	cfg := cf.Load(kv, s.box)
	if in.Action != "start" && in.Action != "stop" && in.Action != "restart" {
		writeError(w, http.StatusBadRequest, "unknown connector action")
		return
	}
	if in.Action != "stop" && cfg.Token == "" {
		writeError(w, http.StatusBadRequest, "save a tunnel token first")
		return
	}
	if s.cloudflared == nil {
		writeError(w, http.StatusConflict, "the connector is not managed by this process")
		return
	}
	switch in.Action {
	case "stop":
		s.cloudflared.Stop()
	case "start", "restart":
		if err := s.cloudflared.Start(cfg.Token); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "cloudflare.connector", "connector "+in.Action, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// cloudflareCheck probes the published hostname. Only this console's own
// hostname is accepted: app hostnames arrive with the Apps tab.
func (s *Server) cloudflareCheck(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Hostnames []string `json:"hostnames"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	kv, err := s.st.Settings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	cfg := cf.Load(kv, s.box)
	console := s.consoleHost(r)
	hosts := in.Hostnames
	if len(hosts) == 0 {
		hosts = []string{console}
	}
	for _, h := range hosts {
		if store.NormalizeHost(h) != console || console == "" {
			writeError(w, http.StatusBadRequest, "only this console's own hostname can be checked until the Apps tab is available")
			return
		}
	}
	if !validConsoleHost(console) {
		writeError(w, http.StatusBadRequest, "set the console hostname on the Sites page first; the check needs the public name")
		return
	}
	checks := s.runCloudflareChecks(r.Context(), console, cfg)
	s.cfMu.Lock()
	s.cfChecks, s.cfChecked = checks, time.Now().Format(time.RFC3339)
	s.cfMu.Unlock()
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "cloudflare.check", "checked "+console, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"hostname": console, "checks": checks})
}

func (s *Server) runCloudflareChecks(ctx context.Context, host string, cfg cf.Settings) []cloudflareCheck {
	snap := cf.Snapshot{}
	if s.cloudflared != nil {
		snap = s.cloudflared.Snapshot()
	}
	checks := []cloudflareCheck{
		{ID: "binary", Label: "Connector installed", OK: snap.Installed, Detail: connectorDetail(snap)},
		{ID: "token", Label: "Tunnel token saved", OK: cfg.Token != "", Detail: tokenDetail(cfg)},
	}

	connectorDetail := ""
	connectorOK := snap.State == cf.StateRunning
	switch {
	case snap.State == cf.StateRunning && snap.Connections > 1:
		connectorDetail = fmt.Sprintf("registered, %d connections", snap.Connections)
	case snap.State == cf.StateRunning && snap.Connections == 1:
		connectorDetail = "registered, 1 connection"
	case snap.State == cf.StateRunning:
		connectorDetail = "registered (connection count unavailable)"
	case snap.State == cf.StateStarting:
		connectorDetail = "starting: waiting for the Cloudflare edge"
	case snap.Error != "":
		connectorDetail = snap.Error
	default:
		connectorDetail = "the connector is stopped"
	}
	checks = append(checks, cloudflareCheck{ID: "connector", Label: "Connector connected to Cloudflare", OK: connectorOK, Detail: connectorDetail})

	dnsCheck, directCheck := hostDnsChecks(ctx, host)
	if strings.HasSuffix(host, ".cfargotunnel.com") {
		dnsCheck = cloudflareCheck{ID: "dns", Label: "Hostname points at Cloudflare", OK: true,
			Detail: "the connector's own hostname needs no public record"}
	}
	checks = append(checks, dnsCheck, directCheck)

	probe := s.probeEdge(ctx, host, "/api/health")
	edgeOK, edgeDetail := probe.cfRay != "", probe.detail
	if probe.err != nil {
		edgeDetail = probe.err.Error()
	}
	checks = append(checks, cloudflareCheck{ID: "edge", Label: "Request reaches the edge", OK: edgeOK, Detail: edgeDetail})

	originOK := edgeOK && probe.status == http.StatusOK && cfg.Nonce != "" && probe.origin == cfg.Nonce
	originDetail := "the console answered through Cloudflare"
	switch {
	case probe.err != nil:
		originDetail = probe.err.Error()
	case !edgeOK:
		originDetail = "no Cloudflare response to compare"
	case originOK:
	case probe.status == http.StatusFound || probe.status == http.StatusSeeOther:
		originDetail = "Cloudflare Access answered instead of the console; add a bypass for /api/health or use a service token"
	default:
		originDetail = fmt.Sprintf("reached the console with HTTP %d but the origin marker is missing", probe.status)
	}
	checks = append(checks, cloudflareCheck{ID: "origin", Label: "Traffic reaches this console", OK: originOK, Detail: originDetail})

	// A bypass on /api/health would hide Access there, so the console root is the
	// path that shows whether a sign-in is required.
	accessProbe := s.probeEdge(ctx, host, "/")
	accessOn := accessProbe.status == http.StatusFound && strings.Contains(accessProbe.location, "cloudflareaccess.com")
	accessDetail := "Access prompts before the console loads"
	if !accessOn {
		if accessProbe.err != nil {
			accessDetail = "cannot tell: " + accessProbe.err.Error()
		} else {
			accessDetail = "no sign-in prompt: anyone with the hostname reaches the console"
		}
	}
	checks = append(checks, cloudflareCheck{ID: "access", Label: "Cloudflare Access protects the console", OK: accessOn, Detail: accessDetail})
	return checks
}

// validConsoleHost keeps the check's outbound URL to a plain hostname. The value
// comes from the admin's own site settings, and this rejects anything that would
// change which host the check connects to.
func validConsoleHost(host string) bool {
	if host == "" || len(host) > 253 || strings.Contains(host, "..") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return strings.Contains(host, ".")
}

func connectorDetail(snap cf.Snapshot) string {
	if snap.Installed && snap.Version != "" {
		return "cloudflared " + snap.Version
	}
	if snap.Installed {
		return "cloudflared is installed"
	}
	return "cloudflared is not installed on this host"
}

func tokenDetail(cfg cf.Settings) string {
	if cfg.Token == "" {
		return "no token saved"
	}
	return "saved and sealed"
}

func lookupHost(ctx context.Context, host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	sort.Strings(addrs)
	return addrs, err
}

func isCloudflareIP(value string) bool {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	for _, prefix := range cloudflareRanges {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

type edgeProbe struct {
	status   int
	location string
	cfRay    string
	origin   string
	detail   string
	err      error
}

// probeEdge asks the public hostname for /api/health, without following the
// Access redirect: the redirect itself is what proves Access is on.
func (s *Server) probeEdge(ctx context.Context, host, path string) edgeProbe {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		return edgeProbe{err: err}
	}
	req.Header.Set("User-Agent", "WAF-Proxy-Check")
	client := &http.Client{
		Timeout: 12 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return edgeProbe{err: errors.New("cannot reach https://" + host + ": " + err.Error())}
	}
	defer resp.Body.Close()
	probe := edgeProbe{
		status:   resp.StatusCode,
		location: resp.Header.Get("Location"),
		cfRay:    resp.Header.Get("CF-Ray"),
		origin:   resp.Header.Get("X-WAF-Origin"),
		detail:   "a Cloudflare edge answered for the hostname",
	}
	if probe.cfRay == "" {
		probe.detail = "the response carries no CF-Ray: it did not come from Cloudflare"
	}
	return probe
}
