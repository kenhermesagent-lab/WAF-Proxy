package api

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/version"
)

// logSecret matches a credential in a log line, in a query string or a JSON
// field, and keeps the key so the line stays readable. Quoted JSON values may
// contain spaces, so they need their own pattern.
var logSecretQuoted = regexp.MustCompile(`(?i)("(?:token|key|secret|password|passwd|authorization|apikey|api_key)"\s*:\s*)"(?:[^"\\]|\\.)*"`)

var logSecret = regexp.MustCompile(`(?i)((?:token|key|secret|password|passwd|authorization|apikey|api_key)["']?\s*[=:]\s*)("[^"]*"|[^&\s,"'}]+)`)

// logQuery strips query strings entirely: access logs put API keys there.
var logQuery = regexp.MustCompile(`\?[^ "\s]+`)

func sanitizeLogLine(line string) string {
	line = logQuery.ReplaceAllString(line, "?[query-redacted]")
	line = logSecretQuoted.ReplaceAllString(line, `${1}"[redacted]"`)
	return logSecret.ReplaceAllString(line, "${1}[redacted]")
}

// readLogTail returns the last lines of the access log, already sanitized, and
// a note when there is nothing to read.
func readLogTail(path string, maxBytes int64, maxLines int) string {
	if path == "" {
		return "access logging is disabled (WAFPROXY_ACCESS_LOG is empty); no log file to include\n"
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Sprintf("access log %s is unreadable: %v\n", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Sprintf("access log %s is unreadable: %v\n", path, err)
	}
	start := info.Size() - maxBytes
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return fmt.Sprintf("access log %s is unreadable: %v\n", path, err)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return fmt.Sprintf("access log %s is unreadable: %v\n", path, err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if start > 0 && len(lines) > 1 {
		lines = lines[1:] // the first line may be a partial record
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	for i, line := range lines {
		lines[i] = sanitizeLogLine(line)
	}
	return strings.Join(lines, "\n") + "\n"
}

type bundleFile struct {
	name string
	body any
}

// diagnosticsBundle returns one zip with everything support needs: versions,
// redacted settings, recent errors, listeners, certificate status and the tail
// of the access log with credentials and query strings removed.
func (s *Server) diagnosticsBundle(w http.ResponseWriter, r *http.Request) {
	settings, _ := s.st.Settings()
	proxies, _ := s.st.ListProxies()
	certs, _ := s.st.ListCerts()
	alerts, _ := s.st.RecentAlerts(50)
	anomalies, _ := s.st.ListAnomalyEvents(50)
	recent, _, _ := s.st.QueryEvents(store.EventFilter{Limit: 200})

	certRows := make([]map[string]any, 0, len(certs))
	certErrors := make([]map[string]any, 0)
	for _, c := range certs {
		expires := ""
		if c.ExpiresAt != nil {
			expires = c.ExpiresAt.UTC().Format(time.RFC3339)
		}
		row := map[string]any{
			"domains": c.Domains, "status": c.Status, "source": c.Source,
			"expires_at": expires, "last_error": c.LastError,
		}
		certRows = append(certRows, row)
		if c.LastError != "" || c.Status == "error" {
			certErrors = append(certErrors, row)
		}
	}
	failedAlerts := make([]map[string]any, 0)
	for _, a := range alerts {
		if a.State == "failed" {
			failedAlerts = append(failedAlerts, map[string]any{
				"channel": a.Channel, "kind": a.Kind, "attempts": a.Attempts,
				"created_at": a.CreatedAt.UTC().Format(time.RFC3339), "payload": a.Payload,
			})
		}
	}
	serverErrors := make([]map[string]any, 0)
	for _, e := range recent {
		if e.Status >= 500 {
			serverErrors = append(serverErrors, map[string]any{
				"ts": e.TS.UTC().Format(time.RFC3339), "host": e.Host, "path": e.Path,
				"status": e.Status, "stage": e.Stage, "action": e.Action,
			})
		}
	}

	files := []bundleFile{
		{"version.json", map[string]any{
			"generated_at": time.Now().UTC().Format(time.RFC3339),
			"version":      version.Version,
			"go_version":   runtime.Version(),
			"platform":     runtime.GOOS + "/" + runtime.GOARCH,
		}},
		{"settings.json", redactSettings(settings)},
		{"listeners.json", map[string]any{
			"wan": s.cfg.ListenWAN, "gui": s.cfg.ListenGUI, "http": s.cfg.ListenHTTP,
			"gui_tls": s.cfg.ListenGUITLS, "gui_host": s.cfg.GUIHost,
			"acme_directory": s.cfg.ACMEDirectory,
			"proxies":        len(proxies),
		}},
		{"certificates.json", certRows},
		{"errors.json", map[string]any{
			"certificates": certErrors,
			"alerts":       failedAlerts,
			"anomalies":    anomalies,
			"upstream_5xx": serverErrors,
		}},
	}

	filename := "wafproxy-diagnostics-" + time.Now().UTC().Format("20060102T150405Z") + ".zip"
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	zw := zip.NewWriter(w)
	write := func(name string, body []byte) error {
		f, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = f.Write(body)
		return err
	}
	for _, bf := range files {
		body, err := json.MarshalIndent(bf.body, "", "  ")
		if err != nil {
			s.log.Warn("diagnostics bundle", "file", bf.name, "err", err)
			continue
		}
		if err := write(bf.name, body); err != nil {
			return
		}
	}
	logTail := readLogTail(os.Getenv("WAFPROXY_ACCESS_LOG"), 256<<10, 500)
	if err := write("logs.txt", []byte("# sanitized access log tail; query strings and credentials removed\n"+logTail)); err != nil {
		return
	}
	if err := write("README.txt", []byte(bundleReadme)); err != nil {
		return
	}
	_ = zw.Close()
}

const bundleReadme = `WAF-Proxy diagnostics bundle

version.json       build and platform
settings.json      configuration with secrets and URL credentials redacted
listeners.json     listen addresses, console TLS and ACME directory
certificates.json  certificate names, status, source and expiry
errors.json        failed alert deliveries, certificate errors, anomalies and 5xx responses
logs.txt           tail of the access log with query strings and credentials removed

No private keys, session tokens, administrator hashes or raw settings secrets are
included. Review logs.txt before sharing if client addresses are sensitive.
`
