package api

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/hostfw"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/streaming"
)

// streamingPayload is the wire format of one service section. The allow list is
// a comma separated string because that is what the form shows.
type streamingPayload struct {
	Enabled      bool   `json:"enabled"`
	ListenIP     string `json:"listen_ip"`
	Protocol     string `json:"protocol"`
	Port         int    `json:"port"`
	PortCount    int    `json:"port_count"`
	Upstream     string `json:"upstream"`
	UpstreamPort int    `json:"upstream_port"`
	Allow        string `json:"allow"`
	MaxConns     int    `json:"max_conns"`
	MaxPerSource int    `json:"max_per_source"`
	IdleSeconds  int    `json:"idle_seconds"`
	MaxDatagram  int    `json:"max_datagram"`
	// A pointer, so an omitted key keeps the saved switch instead of turning
	// the allow requirement off.
	RequireAllow *bool   `json:"require_allow"`
	ListIDs      []int64 `json:"list_ids"`
}

// streamingView is a status plus the catalog seed used to prefill an unsaved
// form and to group the page.
type streamingView struct {
	streaming.Status
	Group    string         `json:"group"`
	Notes    string         `json:"notes"`
	Default  map[string]any `json:"default"`
	Firewall []string       `json:"firewall"`
}

func (s *Server) getStreaming(w http.ResponseWriter, r *http.Request) {
	if !s.requireHostConsole(w, r, "streaming forwarders") {
		return
	}
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
		views = append(views, streamingView{Status: st, Group: def.Group, Notes: def.Notes,
			Default:  s.streamingDefaults(def, kv),
			Firewall: splitEntries(kv["stream_"+def.ID+"_firewall"])})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"services": views,
		"env":      map[string]string{"path": streamingEnvPath(), "error": ""},
	})
}

// streamingDefaults fills a first-visit form from the preset and the addresses
// chosen in the setup wizard. The preset only seeds the form.
func (s *Server) streamingDefaults(def streaming.Service, kv map[string]string) map[string]any {
	upstream := ""
	if lan := strings.TrimSpace(kv["lan_ip"]); lan != "" && lan != "0.0.0.0" {
		upstream = lan
		if def.DefaultPort > 0 {
			upstream = net.JoinHostPort(lan, strconv.Itoa(def.DefaultPort))
		}
	}
	return map[string]any{
		"listen_ip":      strings.TrimSpace(kv["wan_ip"]),
		"protocol":       def.Protocol,
		"port":           def.DefaultPort,
		"port_count":     def.PortCount,
		"upstream":       upstream,
		"upstream_port":  def.DefaultPort,
		"max_conns":      streaming.DefaultMaxConns,
		"max_per_source": streaming.DefaultMaxPerSource,
		"idle_seconds":   streaming.DefaultUDPIdleSeconds,
		"max_datagram":   streaming.DefaultMaxDatagram,
	}
}

func (s *Server) putStreaming(w http.ResponseWriter, r *http.Request) {
	if !s.requireHostConsole(w, r, "streaming forwarders") {
		return
	}
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
	kv, _ := s.db(r).Settings()
	cfg := streaming.Config{
		Enabled: in.Enabled, ListenIP: in.ListenIP, Protocol: in.Protocol, Port: in.Port,
		PortCount: in.PortCount, Upstream: in.Upstream, UpstreamPort: in.UpstreamPort,
		MaxConns: in.MaxConns, MaxPerSource: in.MaxPerSource,
		IdleSeconds: in.IdleSeconds, MaxDatagram: in.MaxDatagram,
		RequireAllow: in.RequireAllow != nil && *in.RequireAllow, ListIDs: in.ListIDs,
	}
	// A page or a cached bundle from before the protocol fields sends neither,
	// so an omitted value keeps what is saved (or the preset on a first save)
	// instead of turning a UDP or both card into one TCP port.
	if strings.TrimSpace(in.Protocol) == "" || in.PortCount == 0 || in.RequireAllow == nil {
		saved := streaming.ConfigFromSettings(def, kv)
		if strings.TrimSpace(in.Protocol) == "" {
			cfg.Protocol = saved.Protocol
		}
		if in.PortCount == 0 {
			cfg.PortCount = saved.PortCount
		}
		if in.RequireAllow == nil {
			cfg.RequireAllow = saved.RequireAllow
		}
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

	if err := s.db(r).SetSettings(streamingSettings(def, normalized)); err != nil {
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
	// Now let the packets through, but only for a listener that came up: opening
	// a port nothing answers on is a hole with no service behind it.
	firewall := s.openStreamPorts(r, def, normalized, kv, applied)
	envPath, envErr := s.streamingEnvFile(def, normalized)

	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "streaming.update",
		def.ID+" enabled="+boolSetting(normalized.Enabled)+" protocol="+normalized.Protocol+
			" ports="+portSpec(normalized)+" upstream="+normalized.Upstream,
		clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"applied":  applied,
		"error":    applyErr,
		"env":      map[string]string{"path": envPath, "error": envErr},
		"firewall": firewall,
	})
}

// openStreamPorts makes the host firewall match the saved configuration: the
// listen range is opened when the forwarder is on, and the range a previous
// save opened is closed when it is turned off or moved. The specs it recorded
// are stored beside the settings, so a later save closes exactly what this one
// opened and nothing the operator added by hand.
func (s *Server) openStreamPorts(r *http.Request, def streaming.Service, cfg streaming.Config, kv map[string]string, applied bool) hostfw.Report {
	failed := cfg.Enabled && (!applied || s.streams == nil)
	key := "stream_" + def.ID + "_firewall"
	want := []hostfw.Spec{}
	if cfg.Enabled && !failed {
		want = hostfw.ForConfig(cfg.Port, cfg.PortCount, cfg.Protocol)
	}
	// A failed rebind left no listener behind, so the range this console opened
	// for the previous configuration is closed rather than left as a hole.
	rep := hostfw.New().Sync(r.Context(), want, splitEntries(kv[key]))

	kept := make([]string, 0, len(want))
	closed := make(map[string]bool, len(rep.Closed))
	for _, spec := range rep.Closed {
		closed[spec] = true
	}
	for _, raw := range splitEntries(kv[key]) {
		if !closed[raw] {
			kept = append(kept, raw)
		}
	}
	kept = append(kept, rep.Opened...)
	if err := s.db(r).SetSettings(map[string]string{key: strings.Join(kept, ",")}); err != nil {
		s.log.Warn("record streaming firewall ports", "service", def.ID, "err", err)
	}
	if failed {
		reason := "the listener did not start"
		if s.streams == nil {
			reason = "no forwarder manager is attached"
		}
		if rep.Detail != "" {
			rep.Detail = reason + " — " + rep.Detail
		} else {
			rep.Detail = reason + ", so the firewall was left alone"
		}
	}
	return rep
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

// streamingSettings is the map a saved configuration writes. It sits beside
// ConfigFromSettings so the two cannot drift.
func streamingSettings(def streaming.Service, cfg streaming.Config) map[string]string {
	prefix := "stream_" + def.ID + "_"
	return map[string]string{
		prefix + "enabled":        boolSetting(cfg.Enabled),
		prefix + "listen_ip":      cfg.ListenIP,
		prefix + "protocol":       cfg.Protocol,
		prefix + "port":           strconv.Itoa(cfg.Port),
		prefix + "port_count":     strconv.Itoa(cfg.PortCount),
		prefix + "upstream":       cfg.Upstream,
		prefix + "upstream_port":  strconv.Itoa(cfg.UpstreamPort),
		prefix + "allow":          strings.Join(cfg.Allow, ","),
		prefix + "max_conns":      strconv.Itoa(cfg.MaxConns),
		prefix + "max_per_source": strconv.Itoa(cfg.MaxPerSource),
		prefix + "idle_seconds":   strconv.Itoa(cfg.IdleSeconds),
		prefix + "max_datagram":   strconv.Itoa(cfg.MaxDatagram),
		prefix + "require_allow":  boolSetting(cfg.RequireAllow),
		prefix + "lists":          joinIDs(cfg.ListIDs),
	}
}

// portSpec names a listen range in one token, e.g. 2456-2458.
func portSpec(cfg streaming.Config) string {
	if cfg.PortCount <= 1 {
		return strconv.Itoa(cfg.Port)
	}
	return fmt.Sprintf("%d-%d", cfg.Port, cfg.Port+cfg.PortCount-1)
}

// streamingPortConflict refuses a listen range already used by the admin GUI,
// the HTTP proxy listener or another forwarder on an overlapping address. TCP
// and UDP on the same number are different sockets, so a game that needs both
// does not collide with a web port.
func (s *Server) streamingPortConflict(def streaming.Service, cfg streaming.Config, kv map[string]string) string {
	// An unset count means one port, the same default Normalize applies.
	count := cfg.PortCount
	if count < 1 {
		count = 1
	}
	overlaps := func(bound string) bool {
		// "0.0.0.0" on either side means the whole host is taken.
		return bound == "" || bound == "0.0.0.0" || cfg.ListenIP == "0.0.0.0" || bound == cfg.ListenIP
	}
	// The WAN listener and the admin GUI are TCP only.
	if protocolHasTCP(cfg.Protocol) {
		for _, reserved := range []struct{ port, addr, name string }{
			{kv["wan_port"], strings.TrimSpace(kv["wan_ip"]), "the WAN proxy listener"},
			{kv["gui_port"], strings.TrimSpace(kv["lan_ip"]), "the admin GUI"},
		} {
			port, err := strconv.Atoi(reserved.port)
			if err != nil || !overlaps(reserved.addr) || !rangesOverlap(cfg.Port, count, port, 1) {
				continue
			}
			return "port " + strconv.Itoa(port) + " is already used by " + reserved.name
		}
	}
	for _, other := range streaming.Catalog {
		if other.ID == def.ID {
			continue
		}
		oc := streaming.ConfigFromSettings(other, kv)
		if !oc.Enabled || !overlaps(strings.TrimSpace(oc.ListenIP)) {
			continue
		}
		if !protocolsOverlap(cfg.Protocol, oc.Protocol) || !rangesOverlap(cfg.Port, count, oc.Port, oc.PortCount) {
			continue
		}
		return "port " + portSpec(cfg) + " overlaps " + other.Label + " on " + portSpec(oc)
	}
	return ""
}

// protocolHasTCP reports whether a configuration binds a TCP socket. An empty
// protocol means tcp, which is what 1.60 saved.
func protocolHasTCP(protocol string) bool { return protocol != "udp" }

// protocolsOverlap reports whether two services contend for a socket. An empty
// protocol means tcp, and "both" binds both, so it collides with either.
func protocolsOverlap(a, b string) bool {
	if a == "" {
		a = "tcp"
	}
	if b == "" {
		b = "tcp"
	}
	return a == b || a == "both" || b == "both"
}

// rangesOverlap reports whether two port ranges share a port.
func rangesOverlap(a, aCount, b, bCount int) bool {
	return a <= b+bCount-1 && b <= a+aCount-1
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
