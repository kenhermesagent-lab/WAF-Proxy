package api

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	updatepkg "github.com/kenhermesagent-lab/waf-proxy-docker/internal/updates"
)

// defaultCrowdSecLAPI is where a stock native install listens.
const defaultCrowdSecLAPI = "http://127.0.0.1:8080"

// consoleCredentials is written by `cscli console enroll`.
const consoleCredentials = "/etc/crowdsec/online_api_credentials.yaml"

// Injectable so a test can describe a host without root or a running engine.
var (
	csLookPath = exec.LookPath
	csStat     = os.Stat
	csOutput   = func(name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
		return cmd.Output()
	}
)

var bouncerKeyRE = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

// crowdsecInstall is what the CrowdSec page needs to offer the one-click
// install: whether this host can take it, whether it is already installed, and
// the progress of a running install.
type crowdsecInstall struct {
	Supported       bool   `json:"supported"`
	Reason          string `json:"reason,omitempty"`
	Platform        string `json:"platform,omitempty"`
	Container       bool   `json:"container"`
	Installed       bool   `json:"installed"`
	EngineRunning   bool   `json:"engine_running"`
	Version         string `json:"version,omitempty"`
	ConsoleEnrolled bool   `json:"console_enrolled"`
	LAPI            string `json:"lapi"`
	Running         bool   `json:"running"`
	Error           string `json:"error,omitempty"`
	Output          string `json:"output,omitempty"`
}

// crowdsecInstallStatus decides whether the console may install the engine.
// A container cannot install host packages, so it keeps the sidecar
// instructions; a host without the root helper stays read-only.
func (s *Server) crowdsecInstallStatus() crowdsecInstall {
	platform, container, hostReady, hostReason := s.updates.HostSupport()
	st := crowdsecInstall{Platform: platform, Container: container, LAPI: defaultCrowdSecLAPI}
	if _, err := csLookPath("cscli"); err == nil {
		st.Installed = true
		st.Version = csPackageVersion()
		st.EngineRunning = csServiceActive()
		if _, err := csStat(consoleCredentials); err == nil {
			st.ConsoleEnrolled = true
		}
	}
	s.csMu.Lock()
	st.Running, st.Error, st.Output = s.csRunning, s.csErr, s.csOutput
	s.csMu.Unlock()
	switch {
	case container:
		st.Reason = "This console runs in a container, so it cannot install host packages. Use the CrowdSec sidecar instead."
	case !hostReady:
		st.Reason = hostReason
	case !s.updates.HelperReady():
		st.Reason = "The privileged host helper is not installed. Re-run sudo ./deploy/install.sh, then reload this page."
	default:
		st.Supported = true
	}
	return st
}

func csPackageVersion() string {
	out, err := csOutput("dpkg-query", "-W", "-f=${Version}", "--", "crowdsec")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func csServiceActive() bool {
	out, err := csOutput("systemctl", "is-active", "crowdsec")
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

func (s *Server) getCrowdSecInstall(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.crowdsecInstallStatus())
}

// startCrowdSecInstall runs the fixed installer in the background: adding the
// CrowdSec repository and installing packages takes minutes, so the page polls
// instead of holding one request open.
func (s *Server) startCrowdSecInstall(w http.ResponseWriter, r *http.Request) {
	st := s.crowdsecInstallStatus()
	if !st.Supported {
		writeError(w, http.StatusConflict, st.Reason)
		return
	}
	s.csMu.Lock()
	if s.csRunning {
		s.csMu.Unlock()
		writeError(w, http.StatusConflict, "a CrowdSec install is already running")
		return
	}
	s.csRunning, s.csErr, s.csOutput = true, "", ""
	s.csMu.Unlock()

	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "crowdsec.install", "install and configure the Security Engine", clientIP(r))
	go s.runCrowdSecInstall()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "installing"})
}

func (s *Server) runCrowdSecInstall() {
	ctx, cancel := context.WithTimeout(context.Background(), 16*time.Minute)
	defer cancel()
	resp, err := s.updates.RunHelper(ctx, updatepkg.HelperRequest{Action: updatepkg.HelperActionCrowdSecInstall})
	message, output := "", ""
	switch {
	case err != nil:
		message = err.Error()
	case !resp.OK:
		message = helperMessage(resp.Error)
		output = redactInstallOutput(resp.Output)
	default:
		output = redactInstallOutput(resp.Output)
		lapi, key := parseCrowdSecInstallOutput(resp.Output)
		if key == "" {
			message = "the installer finished without returning a bouncer key"
			break
		}
		if err := s.saveCrowdSecConfig(true, lapi, key); err != nil {
			message = err.Error()
			break
		}
		s.log.Info("crowdsec installed and bouncer enabled", "lapi", lapi)
	}
	s.csMu.Lock()
	s.csRunning, s.csErr, s.csOutput = false, message, output
	s.csMu.Unlock()
}

// helperMessage turns the helper's terse rejections into something an operator
// can act on.
func helperMessage(m string) string {
	if strings.Contains(m, "unsupported action") {
		return "The host helper is older than this console. Re-run sudo ./deploy/install.sh and try again."
	}
	return m
}

// redactInstallOutput hides the bouncer key the installer prints. The console
// seals it in the database; the browser never needs to see it, and the output is
// polled repeatedly.
func redactInstallOutput(out string) string {
	var b strings.Builder
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "WAFPROXY_KEY=") {
			line = "WAFPROXY_KEY=(saved to the console)"
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return tail(b.String(), 4000)
}

// parseCrowdSecInstallOutput reads the two tagged lines the installer prints.
// The engine's own output shares the stream, so only tagged lines count.
func parseCrowdSecInstallOutput(out string) (lapi, key string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "WAFPROXY_LAPI="); ok {
			lapi = strings.TrimRight(strings.TrimSpace(v), "/")
		}
		if v, ok := strings.CutPrefix(line, "WAFPROXY_KEY="); ok {
			key = strings.TrimSpace(v)
		}
	}
	if !bouncerKeyRE.MatchString(key) {
		key = ""
	}
	if parsed, err := url.Parse(lapi); err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		lapi = defaultCrowdSecLAPI
	}
	return lapi, key
}

// enrollCrowdSecConsole ties the local engine to the operator's CrowdSec
// account. The key is validated here and again by the root helper, then passed
// to cscli as one argv entry.
func (s *Server) enrollCrowdSecConsole(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Key string `json:"key"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	key := strings.TrimSpace(in.Key)
	if !updatepkg.ValidConsoleKey(key) {
		writeError(w, http.StatusBadRequest, "paste the enrollment key from app.crowdsec.net")
		return
	}
	if !s.updates.HelperReady() {
		writeError(w, http.StatusConflict, "the privileged host helper is not running")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	resp, err := s.updates.RunHelper(ctx, updatepkg.HelperRequest{
		Action: updatepkg.HelperActionCrowdSecEnroll, Key: key,
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if !resp.OK {
		message := helperMessage(resp.Error)
		if out := strings.TrimSpace(resp.Output); out != "" {
			message += ": " + tail(out, 400)
		}
		writeError(w, http.StatusBadGateway, message)
		return
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "crowdsec.enroll_console", "engine enrolled in the CrowdSec console", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "enrolled"})
}
