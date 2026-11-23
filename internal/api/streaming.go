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

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/streaming"
)

// streamingPayload is the wire format of one service section. The allow list is
// a comma separated string because that is what the form shows.
type streamingPayload struct {
	Enabled  bool    `json:"enabled"`
	ListenIP string  `json:"listen_ip"`
	Port     int     `json:"port"`
	Upstream string  `json:"upstream"`
	Allow    string  `json:"allow"`
	MaxConns int     `json:"max_conns"`
	ListIDs  []int64 `json:"list_ids"`
}

// streamingView is a status plus the defaults used to prefill an unsaved form.
type streamingView struct {
	streaming.Status
	Default map[string]any `json:"default"`
}

func (s *Server) getStreaming(w http.ResponseWriter, r *http.Request) {
	kv, _ := s.db(r).Settings()
	live := map[string]streaming.Status{}
	if s.streams != nil {
		for _, st := range s.streams.Statuses() {
			live[st.ID] = st
		}
	}
	views := make([]streamingView, 0, len(streaming.Catalog))
	for _, def := range streaming.Catalog {
		st, ok := live[def.ID]
		if !ok {
			st = streaming.Status{ID: def.ID, Label: def.Label, DefaultPort: def.DefaultPort}
		}
		views = append(views, streamingView{Status: st, Default: s.streamingDefaults(def, kv)})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"services": views,
		"env":      map[string]string{"path": streamingEnvPath(), "error": ""},
	})
}

// streamingDefaults fills a first-visit form from the addresses chosen in the
// setup wizard.
func (s *Server) streamingDefaults(def streaming.Service, kv map[string]string) map[string]any {
	upstream := ""
	if lan := strings.TrimSpace(kv["lan_ip"]); lan != "" && lan != "0.0.0.0" {
		upstream = net.JoinHostPort(lan, strconv.Itoa(def.DefaultPort))
	}
	return map[string]any{
		"listen_ip": strings.TrimSpace(kv["wan_ip"]),
		"port":      def.DefaultPort,
		"upstream":  upstream,
		"max_conns": streaming.DefaultMaxConns,
	}
}

func (s *Server) putStreaming(w http.ResponseWriter, r *http.Request) {
	def, ok := streaming.Lookup(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "unknown streaming service")
		return
	}
	var in streamingPayload
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	cfg := streaming.Config{
		Enabled: in.Enabled, ListenIP: in.ListenIP, Port: in.Port,
		Upstream: in.Upstream, MaxConns: in.MaxConns, ListIDs: in.ListIDs,
	}
	if strings.TrimSpace(in.Allow) != "" {
		cfg.Allow = strings.Split(in.Allow, ",")
	}
	normalized, err := cfg.Normalize(def)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	lists, err := s.streamingLists(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	known := make(map[int64]bool, len(lists))
	for _, l := range lists {
		known[l.ID] = true
	}
	for _, id := range normalized.ListIDs {
		if !known[id] {
			writeError(w, http.StatusBadRequest, "unknown list id "+strconv.FormatInt(id, 10))
			return
		}
	}
	kv, _ := s.db(r).Settings()
	if normalized.Enabled {
		// An empty bind address means "all interfaces", which would publish the
		// forwarder on every network the host is on.
		if strings.TrimSpace(normalized.ListenIP) == "" {
			writeError(w, http.StatusBadRequest, "a listen address is required (the WAN address the server should appear from)")
			return
		}
		if msg := s.streamingPortConflict(def, normalized, kv); msg != "" {
			writeError(w, http.StatusBadRequest, msg)
			return
		}
	}

	next := map[string]string{
		"stream_" + def.ID + "_enabled":   boolSetting(normalized.Enabled),
		"stream_" + def.ID + "_listen_ip": normalized.ListenIP,
		"stream_" + def.ID + "_port":      strconv.Itoa(normalized.Port),
		"stream_" + def.ID + "_upstream":  normalized.Upstream,
		"stream_" + def.ID + "_allow":     strings.Join(normalized.Allow, ","),
		"stream_" + def.ID + "_max_conns": strconv.Itoa(normalized.MaxConns),
		"stream_" + def.ID + "_lists":     joinIDs(normalized.ListIDs),
	}
	if err := s.db(r).SetSettings(next); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot save settings")
		return
	}

	applied, applyErr := true, ""
	if s.streams != nil {
		s.streams.SetLists(lists)
		if err := s.streams.Apply(def.ID, normalized); err != nil {
			applied, applyErr = false, err.Error()
		}
	}
	envPath, envErr := s.streamingEnvFile(def, normalized)

	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "streaming.update",
		def.ID+" enabled="+boolSetting(normalized.Enabled)+" port="+strconv.Itoa(normalized.Port)+" upstream="+normalized.Upstream,
		clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"applied": applied,
		"error":   applyErr,
		"env":     map[string]string{"path": envPath, "error": envErr},
	})
}

// streamingLists resolves the named block/allow lists for a forwarder. The
// streaming package works with plain entries so it never imports the store.
func (s *Server) streamingLists(r *http.Request) ([]streaming.List, error) {
	lists, err := s.db(r).ListAccessLists()
	if err != nil {
		return nil, err
	}
	out := make([]streaming.List, 0, len(lists))
	for _, l := range lists {
		out = append(out, streaming.List{
			ID:        l.ID,
			Name:      l.Name,
			Block:     l.Kind == model.ListKindBlock,
			Prefixes:  splitEntries(l.IPs),
			Countries: splitEntries(l.Countries),
		})
	}
	return out, nil
}

// refreshStreamLists pushes an edited list to the forwarders. The listeners are
// not rebound: only the source policy is recompiled, so a media stream that is
// already running keeps playing.
func (s *Server) refreshStreamLists() {
	if s.streams == nil {
		return
	}
	lists, err := s.streamingLists(nil)
	if err != nil {
		s.log.Error("reload streaming lists", "err", err)
		return
	}
	s.streams.SetLists(lists)
	s.streams.RefreshSources()
}

// streamListUsers names the forwarders that attach a list, so deleting it is
// refused while a media port still enforces it.
func (s *Server) streamListUsers(r *http.Request, id int64) []string {
	kv, err := s.db(r).Settings()
	if err != nil {
		return nil
	}
	out := []string{}
	for _, def := range streaming.Catalog {
		for _, ref := range streaming.ConfigFromSettings(def, kv).ListIDs {
			if ref == id {
				out = append(out, "the "+def.Label+" forwarder")
				break
			}
		}
	}
	return out
}

func splitEntries(csv string) []string {
	out := []string{}
	for _, part := range strings.Split(csv, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func joinIDs(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, strconv.FormatInt(id, 10))
	}
	return strings.Join(parts, ",")
}

// streamingPortConflict refuses a port already used by the admin GUI, the HTTP
// proxy listener or another streaming service on an overlapping address, which
// would otherwise fail at bind time with a bare error.
func (s *Server) streamingPortConflict(def streaming.Service, cfg streaming.Config, kv map[string]string) string {
	port := strconv.Itoa(cfg.Port)
	overlaps := func(bound string) bool {
		// "0.0.0.0" on either side means the whole host is taken.
		return bound == "" || bound == "0.0.0.0" || cfg.ListenIP == "0.0.0.0" || bound == cfg.ListenIP
	}
	if kv["wan_port"] == port && overlaps(strings.TrimSpace(kv["wan_ip"])) {
		return "port " + port + " is already used by the WAN proxy listener"
	}
	if kv["gui_port"] == port && overlaps(strings.TrimSpace(kv["lan_ip"])) {
		return "port " + port + " is already used by the admin GUI"
	}
	for _, other := range streaming.Catalog {
		if other.ID == def.ID {
			continue
		}
		oc := streaming.ConfigFromSettings(other, kv)
		if !oc.Enabled || oc.Port != cfg.Port {
			continue
		}
		if overlaps(strings.TrimSpace(oc.ListenIP)) {
			return "port " + port + " is already used by " + other.Label
		}
	}
	return ""
}

// streamingEnvFile mirrors the forwarder settings into the compose env file when
// one is reachable. Host networking publishes ports directly, so a missing file
// is not an error; the path (or the reason it could not be written) is reported
// to the UI instead of failing the save.
// streamingEnvPath resolves the compose env file the page can mirror settings
// into: WAFPROXY_ENV_FILE when set, otherwise deploy/.env or .env beside the
// binary.
func streamingEnvPath() string {
	if path := strings.TrimSpace(os.Getenv("WAFPROXY_ENV_FILE")); path != "" {
		return path
	}
	for _, candidate := range []string{filepath.Join("deploy", ".env"), ".env"} {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate
		}
	}
	return ""
}

func (s *Server) streamingEnvFile(def streaming.Service, cfg streaming.Config) (string, string) {
	path := streamingEnvPath()
	if path == "" {
		return "", ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return path, err.Error()
	}
	prefix := strings.ToUpper(strings.ReplaceAll(def.ID, "-", "_"))
	updated := mergeEnv(string(raw), map[string]string{
		prefix + "_ENABLED":   boolSetting(cfg.Enabled),
		prefix + "_PORT":      strconv.Itoa(cfg.Port),
		prefix + "_LISTEN_IP": cfg.ListenIP,
		prefix + "_UPSTREAM":  cfg.Upstream,
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
		out += "# Streaming forwarders (written by the GUI; host networking needs no port publishing)\n"
		for _, key := range missing {
			out += key + "=" + kv[key] + "\n"
		}
	}
	return out
}

// restartProcess asks the process to exit so the service supervisor (Docker's
// restart policy or systemd Restart=) can bring it back with fresh listeners.
// The request is acknowledged first.
func (s *Server) restartProcess(w http.ResponseWriter, r *http.Request) {
	if s.restartFn == nil {
		writeError(w, http.StatusNotImplemented, "restart is not available in this build")
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "system.restart", "container restart requested", clientIP(r))
	writeJSON(w, http.StatusAccepted, map[string]string{
		"status": "restarting",
		"hint":   "the service stops and starts again; reconnect in a few seconds",
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
