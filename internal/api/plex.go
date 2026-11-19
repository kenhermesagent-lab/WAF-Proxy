package api

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/plex"
)

// plexSettings is the wire format of the Plex page. The allow list is a comma
// separated string because that is what the form shows.
type plexSettings struct {
	Enabled  bool   `json:"enabled"`
	ListenIP string `json:"listen_ip"`
	Port     int    `json:"port"`
	Upstream string `json:"upstream"`
	Allow    string `json:"allow"`
	MaxConns int    `json:"max_conns"`
}

// plexConfig rebuilds the saved configuration from settings.
func (s *Server) plexConfig() plex.Config {
	kv, _ := s.st.Settings()
	port := plex.DefaultPort
	if v, err := strconv.Atoi(kv["plex_port"]); err == nil && v > 0 {
		port = v
	}
	maxConns := plex.DefaultMaxConns
	if v, err := strconv.Atoi(kv["plex_max_conns"]); err == nil && v > 0 {
		maxConns = v
	}
	allow := []string{}
	for _, part := range strings.Split(kv["plex_allow"], ",") {
		if part = strings.TrimSpace(part); part != "" {
			allow = append(allow, part)
		}
	}
	return plex.Config{
		Enabled:  kv["plex_enabled"] == "1",
		ListenIP: kv["plex_listen_ip"],
		Port:     port,
		Upstream: kv["plex_upstream"],
		Allow:    allow,
		MaxConns: maxConns,
	}
}

func (s *Server) getPlex(w http.ResponseWriter, r *http.Request) {
	cfg := s.plexConfig()
	status := plex.Status{Config: cfg}
	if s.plex != nil {
		status = s.plex.Status()
	}
	kv, _ := s.st.Settings()
	envPath, envErr := s.plexEnvFile(false, cfg)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   status,
		"defaults": s.plexDefaults(kv),
		"env":      map[string]string{"path": envPath, "error": envErr},
	})
}

// plexDefaults fills the form for a first visit, using the addresses chosen in
// the setup wizard.
func (s *Server) plexDefaults(kv map[string]string) map[string]any {
	listen := strings.TrimSpace(kv["wan_ip"])
	upstream := ""
	if lan := strings.TrimSpace(kv["lan_ip"]); lan != "" && lan != "0.0.0.0" {
		upstream = net.JoinHostPort(lan, strconv.Itoa(plex.DefaultPort))
	}
	return map[string]any{
		"listen_ip": listen,
		"port":      plex.DefaultPort,
		"upstream":  upstream,
		"max_conns": plex.DefaultMaxConns,
	}
}

func (s *Server) putPlex(w http.ResponseWriter, r *http.Request) {
	var in plexSettings
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	cfg := plex.Config{
		Enabled: in.Enabled, ListenIP: in.ListenIP, Port: in.Port,
		Upstream: in.Upstream, MaxConns: in.MaxConns,
	}
	if strings.TrimSpace(in.Allow) != "" {
		cfg.Allow = strings.Split(in.Allow, ",")
	}
	normalized, err := cfg.Normalize()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	kv, _ := s.st.Settings()
	if normalized.Enabled {
		// An empty bind address means "all interfaces", which would publish the
		// forwarder on every network the host is on.
		if strings.TrimSpace(normalized.ListenIP) == "" {
			writeError(w, http.StatusBadRequest, "a listen address is required (the WAN address Plex should appear from)")
			return
		}
		if msg := plexPortConflict(normalized, kv); msg != "" {
			writeError(w, http.StatusBadRequest, msg)
			return
		}
	}

	next := map[string]string{
		"plex_enabled":   boolSetting(normalized.Enabled),
		"plex_listen_ip": normalized.ListenIP,
		"plex_port":      strconv.Itoa(normalized.Port),
		"plex_upstream":  normalized.Upstream,
		"plex_allow":     strings.Join(normalized.Allow, ","),
		"plex_max_conns": strconv.Itoa(normalized.MaxConns),
	}
	if err := s.st.SetSettings(next); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot save settings")
		return
	}

	applied, applyErr := true, ""
	if s.plex != nil {
		if err := s.plex.Apply(normalized); err != nil {
			applied, applyErr = false, err.Error()
		}
	}
	envPath, envErr := s.plexEnvFile(true, normalized)

	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "plex.update",
		"enabled="+boolSetting(normalized.Enabled)+" port="+strconv.Itoa(normalized.Port)+" upstream="+normalized.Upstream,
		clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"applied":  applied,
		"error":    applyErr,
		"env":      map[string]string{"path": envPath, "error": envErr},
		"settings": next,
	})
}

// plexPortConflict refuses a Plex port that is already the WAN or GUI listener
// on a matching address, which would fail at bind time with a bare error.
func plexPortConflict(cfg plex.Config, kv map[string]string) string {
	port := strconv.Itoa(cfg.Port)
	check := func(name, ipKey, portKey string) string {
		if strings.TrimSpace(kv[portKey]) != port {
			return ""
		}
		bound := strings.TrimSpace(kv[ipKey])
		// "0.0.0.0" on either side means the whole host is taken.
		if bound == "" || bound == "0.0.0.0" || cfg.ListenIP == "0.0.0.0" || bound == cfg.ListenIP {
			return "port " + port + " is already used by the " + name
		}
		return ""
	}
	if msg := check("WAN proxy listener", "wan_ip", "wan_port"); msg != "" {
		return msg
	}
	return check("admin GUI", "lan_ip", "gui_port")
}

// plexEnvFile mirrors the forwarder settings into the compose env file when one
// is reachable. Host networking publishes ports directly, so a missing file is
// not an error; the path (or the reason it could not be written) is reported to
// the UI instead of failing the save.
func (s *Server) plexEnvFile(write bool, cfg plex.Config) (string, string) {
	path := strings.TrimSpace(os.Getenv("WAFPROXY_ENV_FILE"))
	if path == "" {
		for _, candidate := range []string{filepath.Join("deploy", ".env"), ".env"} {
			if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
				path = candidate
				break
			}
		}
	}
	if path == "" {
		return "", ""
	}
	if !write {
		return path, ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return path, err.Error()
	}
	updated := mergeEnv(string(raw), map[string]string{
		"PLEX_ENABLED":   boolSetting(cfg.Enabled),
		"PLEX_PORT":      strconv.Itoa(cfg.Port),
		"PLEX_LISTEN_IP": cfg.ListenIP,
		"PLEX_UPSTREAM":  cfg.Upstream,
	})
	mode := os.FileMode(0o640)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	if err := os.WriteFile(path, []byte(updated), mode); err != nil {
		return path, err.Error()
	}
	return path, ""
}

// mergeEnv rewrites KEY=value lines in place and appends keys that are missing,
// preserving comments and unrelated settings.
func mergeEnv(src string, kv map[string]string) string {
	lines := strings.Split(src, "\n")
	seen := map[string]bool{}
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, _, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if v, wanted := kv[key]; wanted {
			lines[i] = key + "=" + v
			seen[key] = true
		}
	}
	out := strings.Join(lines, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	missing := make([]string, 0, len(kv))
	for key := range kv {
		if !seen[key] {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		out += "# Plex forwarder (written by the GUI; host networking needs no port publishing)\n"
		for _, key := range missing {
			out += key + "=" + kv[key] + "\n"
		}
	}
	return out
}

// restart asks the process to exit so the container's restart policy can bring
// it back with fresh listeners. The request is acknowledged first.
func (s *Server) restartProcess(w http.ResponseWriter, r *http.Request) {
	if s.restartFn == nil {
		writeError(w, http.StatusNotImplemented, "restart is not available in this build")
		return
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "system.restart", "container restart requested", clientIP(r))
	writeJSON(w, http.StatusAccepted, map[string]string{
		"status": "restarting",
		"hint":   "the container stops and starts again; reconnect in a few seconds",
	})
	go func() {
		time.Sleep(500 * time.Millisecond)
		s.restartFn()
	}()
}

func boolSetting(v bool) string {
	if v {
		return "1"
	}
	return "0"
}
