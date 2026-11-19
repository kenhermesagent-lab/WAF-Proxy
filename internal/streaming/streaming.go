// Package streaming forwards media-server traffic (Plex, Jellyfin, ...) through
// the gateway as a transparent TCP relay.
//
// These servers publish their own TLS identities (Plex clients validate the
// *.plex.direct names that encode the server address), so terminating TLS here
// would break them. A byte relay keeps the handshake end to end and makes every
// client appear to come from the gateway's LAN address, which is what the
// server's whitelist needs.
//
// The relay is outside the HTTP pipeline: the WAF and access gate cannot see it,
// but the source allowlist, the connection cap and the ban engine do.
package streaming

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultMaxConns caps concurrent streams for a service.
	DefaultMaxConns = 256
	dialTimeout     = 8 * time.Second
	// Media players pause for long periods, so the idle ceiling is generous.
	idleTimeout = 30 * time.Minute
	// refusalWindow is how often one banned source can produce an event per
	// service; repeat attempts inside the window are counted, not logged.
	refusalWindow = time.Minute
)

// Service is one supported media server.
type Service struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	DefaultPort int    `json:"default_port"`
}

// Catalog lists the services the gateway can forward. Adding an entry here is
// enough to get a section in the Streaming page and its own settings.
var Catalog = []Service{
	{ID: "plex", Label: "Plex", DefaultPort: 32400},
	{ID: "jellyfin", Label: "Jellyfin", DefaultPort: 8096},
}

// Lookup returns the catalog entry for an id.
func Lookup(id string) (Service, bool) {
	for _, s := range Catalog {
		if s.ID == id {
			return s, true
		}
	}
	return Service{}, false
}

// Config is the operator-visible configuration of one service.
type Config struct {
	Enabled  bool     `json:"enabled"`
	ListenIP string   `json:"listen_ip"`
	Port     int      `json:"port"`
	Upstream string   `json:"upstream"`
	Allow    []string `json:"allow"`
	MaxConns int      `json:"max_conns"`
}

// Event is a refusal or a cut stream, handed to the sink that logs it.
type Event struct {
	Service string
	Label   string
	Port    int
	Addr    netip.Addr
	Detail  string
}

// Status is the configuration plus live state for one service.
type Status struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	DefaultPort int    `json:"default_port"`
	Config
	Bound      bool   `json:"bound"`
	ListenAddr string `json:"listen_addr"`
	Active     int64  `json:"active"`
	Total      uint64 `json:"total"`
	Blocked    uint64 `json:"blocked"`
	Banned     uint64 `json:"banned"`
	Dropped    uint64 `json:"dropped"`
	LastError  string `json:"last_error"`
}

// ConfigFromSettings rebuilds a saved configuration. Values live under
// stream_<id>_*; the bare plex_* keys written by 1.1.1 are still read when the
// new key is missing, so an upgraded install keeps working.
func ConfigFromSettings(def Service, kv map[string]string) Config {
	get := func(field string) string {
		if v := kv["stream_"+def.ID+"_"+field]; v != "" {
			return v
		}
		if def.ID == "plex" {
			return kv["plex_"+field]
		}
		return ""
	}
	port := def.DefaultPort
	if v, err := strconv.Atoi(get("port")); err == nil && v > 0 {
		port = v
	}
	maxConns := DefaultMaxConns
	if v, err := strconv.Atoi(get("max_conns")); err == nil && v > 0 {
		maxConns = v
	}
	allow := []string{}
	for _, part := range strings.Split(get("allow"), ",") {
		if part = strings.TrimSpace(part); part != "" {
			allow = append(allow, part)
		}
	}
	return Config{
		Enabled:  get("enabled") == "1",
		ListenIP: get("listen_ip"),
		Port:     port,
		Upstream: get("upstream"),
		Allow:    allow,
		MaxConns: maxConns,
	}
}

// Normalize validates a configuration and fills in defaults.
func (c Config) Normalize(def Service) (Config, error) {
	c.ListenIP = strings.TrimSpace(c.ListenIP)
	if c.Port == 0 {
		c.Port = def.DefaultPort
	}
	if c.Port < 1 || c.Port > 65535 {
		return c, errors.New("port must be between 1 and 65535")
	}
	if c.ListenIP != "" && net.ParseIP(c.ListenIP) == nil {
		return c, errors.New("listen address must be an IP address")
	}
	if c.MaxConns == 0 {
		c.MaxConns = DefaultMaxConns
	}
	if c.MaxConns < 1 || c.MaxConns > 4096 {
		return c, errors.New("max_conns must be between 1 and 4096")
	}

	host, port, err := splitHostPort(c.Upstream, def.DefaultPort)
	if err != nil {
		return c, err
	}
	c.Upstream = net.JoinHostPort(host, port)

	allow := make([]string, 0, len(c.Allow))
	for _, raw := range c.Allow {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		prefix, err := parsePrefix(raw)
		if err != nil {
			return c, fmt.Errorf("allowed source %q: %w", raw, err)
		}
		allow = append(allow, prefix)
	}
	c.Allow = allow
	return c, nil
}

func splitHostPort(raw string, defaultPort int) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("the server address is required")
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return "", "", errors.New("the server address is not a valid URL")
		}
		raw = u.Host
	}
	if !strings.Contains(raw, ":") {
		if err := validHost(raw); err != nil {
			return "", "", err
		}
		return raw, strconv.Itoa(defaultPort), nil
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", "", errors.New("the server address must be host or host:port")
	}
	if err := validHost(host); err != nil {
		return "", "", err
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", "", errors.New("the server port is not valid")
	}
	return host, port, nil
}

// validHost accepts an IP address or a plain hostname, so a pasted sentence is
// a form error rather than a listener that can never connect.
func validHost(host string) error {
	if host == "" {
		return errors.New("the server address has no host")
	}
	if len(host) > 253 {
		return errors.New("the server address is too long")
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	for _, r := range host {
		ok := r == '.' || r == '-' || r == '_' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return errors.New("the server address is not a hostname or IP address")
		}
	}
	return nil
}

func parsePrefix(raw string) (string, error) {
	if p, err := netip.ParsePrefix(raw); err == nil {
		return p.Masked().String(), nil
	}
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return "", errors.New("not an IP address or CIDR")
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()).String(), nil
}

func prefixesFor(allow []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(allow))
	for _, raw := range allow {
		if p, err := netip.ParsePrefix(raw); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// Manager owns one listener per enabled service. Apply rebinds a single service
// without touching the others.
type Manager struct {
	log *slog.Logger

	mu       sync.Mutex
	services map[string]*runtime

	bans   atomic.Value // func(netip.Addr) bool
	events atomic.Value // func(Event)

	refusals *throttle
	now      func() time.Time
}

// runtime is the live state of one listener.
type runtime struct {
	def   Service
	cfg   Config
	allow []netip.Prefix
	ln    net.Listener
	done  chan struct{}
	wg    sync.WaitGroup

	connMu sync.Mutex
	conns  map[*relay]struct{}

	active  atomic.Int64
	total   atomic.Uint64
	blocked atomic.Uint64
	banned  atomic.Uint64
	dropped atomic.Uint64
	lastErr atomic.Value // string
}

// relay is one accepted pair of sockets, kept so a ban can cut a stream that is
// already running instead of only refusing new ones.
type relay struct {
	client   net.Conn
	upstream net.Conn
	addr     netip.Addr
}

// New creates a manager with no listeners.
func New(log *slog.Logger) *Manager {
	return &Manager{
		log:      log,
		services: make(map[string]*runtime),
		refusals: newThrottle(refusalWindow),
		now:      time.Now,
	}
}

// SetBans attaches the ban lookup. Without it an address banned on 443 could
// still stream through a forwarded port.
func (m *Manager) SetBans(fn func(netip.Addr) bool) {
	if fn != nil {
		m.bans.Store(fn)
	}
}

// SetEventSink installs the callback that records refusals and cut streams.
func (m *Manager) SetEventSink(fn func(Event)) {
	if fn != nil {
		m.events.Store(fn)
	}
}

func (m *Manager) isBanned(addr netip.Addr) bool {
	if fn, ok := m.bans.Load().(func(netip.Addr) bool); ok && fn != nil {
		return fn(addr)
	}
	return false
}

func (m *Manager) emit(ev Event) {
	if fn, ok := m.events.Load().(func(Event)); ok && fn != nil {
		fn(ev)
	}
}

// ApplyAll configures every catalog service. Services missing from cfgs are
// stopped. The first error is returned after the others have been attempted.
func (m *Manager) ApplyAll(cfgs map[string]Config) error {
	var first error
	for _, def := range Catalog {
		if err := m.Apply(def.ID, cfgs[def.ID]); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Apply rebinds one service. An error still leaves the saved state inspected by
// Status, so the UI can show why the listener did not start.
func (m *Manager) Apply(id string, cfg Config) error {
	def, ok := Lookup(id)
	if !ok {
		return fmt.Errorf("unknown streaming service %q", id)
	}

	m.mu.Lock()
	m.stopLocked(id)
	// The runtime is kept even when the service is off, so Status still reports
	// the saved settings the page shows.
	rt := &runtime{def: def, cfg: cfg, conns: make(map[*relay]struct{})}
	rt.lastErr.Store("")
	m.services[id] = rt
	var listenErr error
	if cfg.Enabled {
		norm, err := cfg.Normalize(def)
		if err != nil {
			rt.lastErr.Store(err.Error())
			m.mu.Unlock()
			return err
		}
		rt.cfg = norm
		addr := net.JoinHostPort(norm.ListenIP, strconv.Itoa(norm.Port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			rt.lastErr.Store(err.Error())
			listenErr = fmt.Errorf("listen on %s: %w", addr, err)
		} else {
			rt.ln, rt.done, rt.allow = ln, make(chan struct{}), prefixesFor(norm.Allow)
			m.log.Info("streaming forwarder listening", "service", id, "addr", ln.Addr().String(), "upstream", norm.Upstream)
		}
	}
	m.mu.Unlock()

	if rt.ln != nil {
		rt.wg.Add(1)
		go m.accept(rt)
	}
	return listenErr
}

// Close stops every listener.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id := range m.services {
		m.stopLocked(id)
	}
}

func (m *Manager) stopLocked(id string) {
	rt, ok := m.services[id]
	if !ok {
		return
	}
	if rt.done != nil {
		close(rt.done)
	}
	if rt.ln != nil {
		_ = rt.ln.Close()
	}
	rt.connMu.Lock()
	for r := range rt.conns {
		_ = r.client.Close()
		_ = r.upstream.Close()
	}
	rt.connMu.Unlock()
	rt.wg.Wait()
	delete(m.services, id)
}

// Statuses returns one entry per catalog service, configured or not.
func (m *Manager) Statuses() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(Catalog))
	for _, def := range Catalog {
		st := Status{ID: def.ID, Label: def.Label, DefaultPort: def.DefaultPort}
		rt, ok := m.services[def.ID]
		if !ok {
			out = append(out, st)
			continue
		}
		st.Config = rt.cfg
		st.Active = rt.active.Load()
		st.Total = rt.total.Load()
		st.Blocked = rt.blocked.Load()
		st.Banned = rt.banned.Load()
		st.Dropped = rt.dropped.Load()
		if v, ok := rt.lastErr.Load().(string); ok {
			st.LastError = v
		}
		if rt.ln != nil {
			st.Bound = true
			st.ListenAddr = rt.ln.Addr().String()
		}
		out = append(out, st)
	}
	return out
}

// DropBanned closes every open stream whose source matches, which is how a ban
// reaches a stream that started before it. It returns the number of streams cut.
func (m *Manager) DropBanned(match func(netip.Addr) bool, detail string) int {
	if match == nil {
		return 0
	}
	type victim struct {
		rt *runtime
		r  *relay
	}
	var doomed []victim

	m.mu.Lock()
	for _, rt := range m.services {
		rt.connMu.Lock()
		for r := range rt.conns {
			if match(r.addr) {
				doomed = append(doomed, victim{rt, r})
			}
		}
		rt.connMu.Unlock()
	}
	m.mu.Unlock()

	for _, v := range doomed {
		// Closing both ends unblocks the two copy goroutines immediately.
		_ = v.r.client.Close()
		_ = v.r.upstream.Close()
		v.rt.dropped.Add(1)
		m.emit(Event{Service: v.rt.def.ID, Label: v.rt.def.Label, Port: v.rt.cfg.Port, Addr: v.r.addr, Detail: detail})
	}
	return len(doomed)
}

func (m *Manager) accept(rt *runtime) {
	defer rt.wg.Done()
	for {
		conn, err := rt.ln.Accept()
		if err != nil {
			select {
			case <-rt.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			rt.lastErr.Store(err.Error())
			m.log.Warn("streaming accept", "service", rt.def.ID, "err", err)
			// Back off briefly so a persistently failing listener cannot spin.
			select {
			case <-rt.done:
				return
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		if rt.active.Load() >= int64(rt.cfg.MaxConns) {
			rt.blocked.Add(1)
			_ = conn.Close()
			continue
		}
		addr, ok := remoteAddr(conn.RemoteAddr())
		if !ok || !allowed(rt.allow, addr) {
			rt.blocked.Add(1)
			_ = conn.Close()
			continue
		}
		if m.isBanned(addr) {
			rt.banned.Add(1)
			_ = conn.Close()
			m.refuse(rt, addr)
			continue
		}
		rt.total.Add(1)
		rt.active.Add(1)
		rt.wg.Add(1)
		go func(client net.Conn) {
			defer rt.wg.Done()
			defer rt.active.Add(-1)
			m.handle(rt, client, addr)
		}(conn)
	}
}

// refuse reports a refused banned attempt at most once per window per source,
// so a retry loop cannot fill the event log.
func (m *Manager) refuse(rt *runtime, addr netip.Addr) {
	emit, suppressed := m.refusals.allow(rt.def.ID, addr, m.now())
	if !emit {
		return
	}
	detail := fmt.Sprintf("banned source refused on the %s port", rt.def.Label)
	if suppressed > 0 {
		detail += fmt.Sprintf(" (%d more attempts suppressed)", suppressed)
	}
	m.emit(Event{Service: rt.def.ID, Label: rt.def.Label, Port: rt.cfg.Port, Addr: addr, Detail: detail})
}

func (m *Manager) handle(rt *runtime, client net.Conn, addr netip.Addr) {
	defer client.Close()

	upstream, err := net.DialTimeout("tcp", rt.cfg.Upstream, dialTimeout)
	if err != nil {
		rt.lastErr.Store(err.Error())
		m.log.Warn("streaming upstream dial failed", "service", rt.def.ID, "upstream", rt.cfg.Upstream, "err", err)
		return
	}
	defer upstream.Close()

	// Track before checking the ban: a ban that lands from here on finds the
	// relay in conns and cuts it, and one that landed during the dial is
	// caught by the check itself.
	r := &relay{client: client, upstream: upstream, addr: addr}
	rt.track(r)
	defer rt.untrack(r)

	if m.isBanned(addr) {
		rt.dropped.Add(1)
		m.emit(Event{Service: rt.def.ID, Label: rt.def.Label, Port: rt.cfg.Port, Addr: addr,
			Detail: fmt.Sprintf("stream closed by active ban on the %s port", rt.def.Label)})
		return
	}

	if tcp, ok := client.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
	relayCopy(idleConn{Conn: client}, idleConn{Conn: upstream})
}

func (rt *runtime) track(r *relay) {
	rt.connMu.Lock()
	rt.conns[r] = struct{}{}
	rt.connMu.Unlock()
}

func (rt *runtime) untrack(r *relay) {
	rt.connMu.Lock()
	delete(rt.conns, r)
	rt.connMu.Unlock()
}

// relayCopy copies both directions and tears the pair down when either side
// finishes, which is what closes a stream promptly.
func relayCopy(client, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, client)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		done <- struct{}{}
	}()
	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

// idleConn refreshes the deadline on every operation so an idle connection is
// eventually reclaimed while a long stream is never cut in the middle.
type idleConn struct {
	net.Conn
}

func (c idleConn) Read(b []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(idleTimeout))
	return c.Conn.Read(b)
}

func (c idleConn) Write(b []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(idleTimeout))
	return c.Conn.Write(b)
}

func allowed(allow []netip.Prefix, addr netip.Addr) bool {
	if len(allow) == 0 {
		return true
	}
	for _, p := range allow {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func remoteAddr(remote net.Addr) (netip.Addr, bool) {
	tcp, ok := remote.(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// throttle collapses repeated refusals from one source and service into one
// event per window, remembering how many were folded in.
type throttle struct {
	mu     sync.Mutex
	window time.Duration
	seen   map[refusalKey]*refusalEntry
}

type refusalKey struct {
	service string
	addr    netip.Addr
}

type refusalEntry struct {
	last       time.Time
	suppressed int
}

func newThrottle(window time.Duration) *throttle {
	return &throttle{window: window, seen: make(map[refusalKey]*refusalEntry)}
}

// allow reports whether an event should be emitted now, and how many attempts
// were folded into it since the last one.
func (t *throttle) allow(service string, addr netip.Addr, now time.Time) (bool, int) {
	key := refusalKey{service: service, addr: addr}
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.seen[key]
	if !ok {
		if len(t.seen) >= 4096 {
			t.prune(now)
		}
		t.seen[key] = &refusalEntry{last: now}
		return true, 0
	}
	if now.Sub(e.last) < t.window {
		e.suppressed++
		return false, 0
	}
	suppressed := e.suppressed
	e.suppressed = 0
	e.last = now
	return true, suppressed
}

// prune drops entries that have been quiet for ten windows; a retry loop keeps
// its own entry warm, so the bound holds.
func (t *throttle) prune(now time.Time) {
	for k, e := range t.seen {
		if now.Sub(e.last) > 10*t.window {
			delete(t.seen, k)
		}
	}
}
