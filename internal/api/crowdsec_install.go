package api

import (
	"context"
	"errors"
	"io/fs"
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
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	// ConsoleState is what `cscli console status` reports for the engine:
	// "enrolled" once the console accepted it, "pending" while the request
	// awaits acceptance, "none" without credentials and "unknown" otherwise.
	ConsoleState  string `json:"console_state"`
	ConsoleDetail string `json:"console_detail,omitempty"`
	// ConsolePlan and ConsoleDecision decide whether console-pushed decisions
	// and blocklists actually reach this engine.
	ConsolePlan           string `json:"console_plan,omitempty"`
	ConsoleCAPI           string `json:"console_capi,omitempty"`
	ConsoleDecision       string `json:"console_decision,omitempty"`
	ConsoleDecisionActive bool   `json:"console_decision_active"`
	ConsolePAPI           string `json:"console_papi,omitempty"`
	LAPI                  string `json:"lapi"`
	Running               bool   `json:"running"`
	Error                 string `json:"error,omitempty"`
	Output                string `json:"output,omitempty"`
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
		info := s.consoleInfo()
		st.ConsoleState, st.ConsoleDetail = info.State, info.Detail
		st.ConsolePlan, st.ConsoleCAPI = info.Plan, info.CAPI
		st.ConsoleDecision, st.ConsoleDecisionActive = info.Decision, info.DecisionsActive
		st.ConsolePAPI = info.PAPI
		// ConsoleEnrolled records that credentials exist on disk; the state is
		// what the console reports and is authoritative for display.
		if _, err := csStat(consoleCredentials); err == nil {
			st.ConsoleEnrolled = true
		}
	} else {
		st.ConsoleState = "none"
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

// consoleInfo is everything the CrowdSec page reports about the link between
// this engine and the CrowdSec console.
type consoleInfo struct {
	State           string
	Detail          string
	Plan            string
	CAPI            string
	Decision        string
	DecisionsActive bool
	PAPI            string
}

// consoleInfo reports whether the console accepted this engine and whether
// console-pushed decisions will reach it. Enrolling only queues the request, so
// the status table is the only honest answer; the credential file is checked
// last and only to tell "not linked" from "cannot tell", because it is
// root-only and an unprivileged stat may simply be denied.
func (s *Server) consoleInfo() consoleInfo {
	_, statErr := csStat(consoleCredentials)
	return consoleInfoFromRows(s.consoleRows(), statErr)
}

// consoleInfoFromRows separates "the status table says nothing" from "there are
// no credentials at all", and never turns a permission error into "not linked".
func consoleInfoFromRows(rows map[string]string, statErr error) consoleInfo {
	info := consoleInfo{
		State:    "unknown",
		Plan:     plainCell(rowValue(rows, "plan")),
		CAPI:     plainCell(rowValue(rows, "central api (capi)", "central api")),
		Decision: plainCell(rowValue(rows, "decision management")),
		PAPI:     plainCell(rowValue(rows, "papi subscriptions")),
	}
	info.State, info.Detail = consoleStatusFromRows(rows)
	info.DecisionsActive = decisionRowActive(info.Decision)
	if (info.State == "none" || info.State == "unknown") && errors.Is(statErr, fs.ErrNotExist) {
		info.State, info.Detail = "none", ""
	}
	return info
}

// consoleRows runs `cscli console status` at most once every 15 seconds: the
// CrowdSec page polls while an install runs.
func (s *Server) consoleRows() map[string]string {
	s.csMu.Lock()
	rows, at := s.csConsoleRows, s.csConsoleAt
	s.csMu.Unlock()
	if rows != nil && time.Since(at) < 15*time.Second {
		return rows
	}
	out, err := s.crowdsecConsoleStatus()
	rows = map[string]string{}
	if err == nil {
		rows = parseConsoleRows(out)
	}
	s.csMu.Lock()
	s.csConsoleRows, s.csConsoleAt = rows, time.Now()
	s.csMu.Unlock()
	return rows
}

// crowdsecConsoleStatus runs `cscli console status` through the root helper,
// because the console credential files it reads are root-only. Hosts without
// the helper fall back to running cscli directly.
func (s *Server) crowdsecConsoleStatus() (string, error) {
	if s.updates.HelperReady() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		resp, err := s.updates.RunHelper(ctx, updatepkg.HelperRequest{Action: updatepkg.HelperActionCrowdSecStatus})
		if err != nil {
			return "", err
		}
		if resp.OK {
			return resp.Output, nil
		}
		if !strings.Contains(resp.Error, "unsupported action") {
			return "", errors.New(resp.Error)
		}
	}
	out, err := csOutput("cscli", "console", "status")
	return string(out), err
}

// parseConsoleRows turns the table `cscli console status` prints into a map of
// lowercased label to value, so Enrolled, Plan, Decision management and PAPI
// subscriptions all come from the engine instead of being guessed.
func parseConsoleRows(out string) map[string]string {
	rows := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		cells, ok := tableCells(line)
		if !ok || len(cells) < 2 {
			continue
		}
		label := strings.ToLower(strings.TrimSpace(cells[0]))
		value := strings.TrimSpace(cells[1])
		if label == "" || value == "" || label == "console connection" {
			continue
		}
		rows[label] = value
	}
	return rows
}

// consoleStatusFromRows classifies the Enrolled row. A pending request shows a
// cross or "not enrolled"; the console sets "enrolled" once it accepted the
// engine.
func consoleStatusFromRows(rows map[string]string) (state, detail string) {
	detail, ok := rows["enrolled"]
	if !ok {
		return "unknown", ""
	}
	value := strings.ToLower(detail)
	switch {
	case strings.Contains(value, "not enrolled"),
		strings.Contains(value, "pending"),
		strings.Contains(value, "✗"),
		strings.Contains(value, "✘"),
		strings.Contains(value, "❌"):
		return "pending", detail
	case strings.Contains(value, "enrolled"):
		return "enrolled", detail
	}
	return "unknown", detail
}

// rowValue returns the first non-empty value among the given labels.
func rowValue(rows map[string]string, labels ...string) string {
	for _, label := range labels {
		if v := strings.TrimSpace(rows[label]); v != "" {
			return v
		}
	}
	return ""
}

// plainCell drops the tick or cross a status cell starts with.
func plainCell(v string) string {
	v = strings.TrimSpace(v)
	for _, prefix := range []string{"✅", "✔️", "✔", "✓", "❌", "✗", "✘", "⚠️", "⚠"} {
		v = strings.TrimSpace(strings.TrimPrefix(v, prefix))
	}
	return v
}

// decisionRowActive reads the Decision management row: the console can only
// push decisions and blocklists when it is active, which needs a plan that
// includes decision management.
func decisionRowActive(v string) bool {
	l := strings.ToLower(v)
	if !strings.Contains(l, "active") {
		return false
	}
	for _, off := range []string{"inactive", "not active", "✗", "✘", "❌", "not included", "requires"} {
		if strings.Contains(l, off) {
			return false
		}
	}
	return true
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
	if !s.requireHostConsole(w, r, "the CrowdSec engine") {
		return
	}
	var in struct {
		ConsoleKey string `json:"console_key"`
	}
	// The body is optional: an operator without a CrowdSec account installs
	// without a key, and enrolls later from the card below.
	if r.ContentLength > 0 {
		if err := decode(r, &in); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
	}
	in.ConsoleKey = strings.TrimSpace(in.ConsoleKey)
	if in.ConsoleKey != "" && !updatepkg.ValidConsoleKey(in.ConsoleKey) {
		writeError(w, http.StatusBadRequest, "paste the enrollment key from app.crowdsec.net")
		return
	}
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
	s.csConsoleKey = in.ConsoleKey
	s.csMu.Unlock()

	sess := sessionFrom(r)
	action := "install and configure the Security Engine"
	if in.ConsoleKey != "" {
		action += " and link it to the CrowdSec console"
	}
	s.db(r).AddAudit(sess.Username, "crowdsec.install", action, clientIP(r))
	go s.runCrowdSecInstall()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "installing"})
}

func (s *Server) runCrowdSecInstall() {
	s.csMu.Lock()
	consoleKey := s.csConsoleKey
	s.csMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 16*time.Minute)
	defer cancel()
	resp, err := s.updates.RunHelper(ctx, updatepkg.HelperRequest{
		Action: updatepkg.HelperActionCrowdSecInstall, Key: consoleKey,
	})
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
		if enrollErr := parseConsoleEnrollError(resp.Output); enrollErr != "" {
			message = "the engine and bouncer are ready, but the console enrollment failed: " + enrollErr
		}
		s.log.Info("crowdsec installed and bouncer enabled", "lapi", lapi)
	}
	s.csMu.Lock()
	s.csRunning, s.csErr, s.csOutput = false, message, output
	s.csMu.Unlock()
}

// parseConsoleEnrollError reads the line the installer prints when it could not
// link the engine, so the install can still succeed with a clear reason.
func parseConsoleEnrollError(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "WAFPROXY_CONSOLE_ERROR="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// restartCrowdSec applies an accepted console enrollment, which the engine only
// picks up when it restarts.
func (s *Server) restartCrowdSec(w http.ResponseWriter, r *http.Request) {
	if !s.requireHostConsole(w, r, "the CrowdSec engine") {
		return
	}
	if !s.updates.HelperReady() {
		writeError(w, http.StatusConflict, "the privileged host helper is not running")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	resp, err := s.updates.RunHelper(ctx, updatepkg.HelperRequest{Action: updatepkg.HelperActionCrowdSecRestart})
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
	s.db(r).AddAudit(sess.Username, "crowdsec.restart", "restart the Security Engine", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "restarted"})
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
	if !s.requireHostConsole(w, r, "the CrowdSec engine") {
		return
	}
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
	s.db(r).AddAudit(sess.Username, "crowdsec.enroll_console", "engine enrolled in the CrowdSec console", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "enrolled"})
}
