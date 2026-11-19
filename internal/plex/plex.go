// Package plex forwards Plex Media Server traffic through the gateway.
//
// Plex can be configured to trust only a list of networks ("List of IP
// addresses and networks that are allowed without auth"), so a Plex server
// behind this gateway sees every client as coming from the proxy's LAN address.
//
// The forwarder is a transparent TCP relay rather than an HTTP reverse proxy:
// Plex clients validate certificates for the *.plex.direct names that encode
// the server's IP, which this gateway cannot mint, and the relay passes those
// handshakes through untouched. The trade-off is that the payload is TLS and is
// therefore not inspected by the WAF; enable the forwarder only for the Plex
// port and keep the HTTP proxies on their own hostnames.
package plex

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

// Defaults for a configuration that has not been filled in yet.
const (
	DefaultPort     = 32400
	DefaultMaxConns = 256
	dialTimeout     = 8 * time.Second
	// Plex pauses streams for long periods, so the idle ceiling is generous.
	idleTimeout = 30 * time.Minute
)

// Config is the operator-visible Plex forwarder configuration.
type Config struct {
	Enabled  bool     `json:"enabled"`
	ListenIP string   `json:"listen_ip"`
	Port     int      `json:"port"`
	Upstream string   `json:"upstream"`
	Allow    []string `json:"allow"`
	MaxConns int      `json:"max_conns"`
}

// Status is the configuration plus live state.
type Status struct {
	Config
	Bound      bool   `json:"bound"`
	ListenAddr string `json:"listen_addr"`
	Active     int64  `json:"active"`
	Total      uint64 `json:"total"`
	Blocked    uint64 `json:"blocked"`
	Banned     uint64 `json:"banned"`
	LastError  string `json:"last_error"`
}

// Normalize validates a configuration and fills in defaults. It returns a copy;
// the caller never shares the slice it passed in.
func (c Config) Normalize() (Config, error) {
	c.ListenIP = strings.TrimSpace(c.ListenIP)
	if c.Port == 0 {
		c.Port = DefaultPort
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

	host, port, err := splitHostPort(c.Upstream)
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

func splitHostPort(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("the Plex server address is required")
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return "", "", errors.New("the Plex server address is not a valid URL")
		}
		raw = u.Host
	}
	if !strings.Contains(raw, ":") {
		if err := validHost(raw); err != nil {
			return "", "", err
		}
		return raw, strconv.Itoa(DefaultPort), nil
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", "", errors.New("the Plex server address must be host or host:port")
	}
	if err := validHost(host); err != nil {
		return "", "", err
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", "", errors.New("the Plex server port is not valid")
	}
	return host, port, nil
}

// validHost accepts an IP address or a plain hostname. Whitespace and other
// characters that would end up verbatim in a dial address are refused, so a
// pasted sentence is a form error rather than a listener that cannot connect.
func validHost(host string) error {
	if host == "" {
		return errors.New("the Plex server address has no host")
	}
	if len(host) > 253 {
		return errors.New("the Plex server address is too long")
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	for _, r := range host {
		ok := r == '.' || r == '-' || r == '_' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return errors.New("the Plex server address is not a hostname or IP address")
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

// Manager owns the listener lifecycle. Apply can be called at any time to
// rebind, disable or reconfigure the forwarder without restarting the process.
type Manager struct {
	log *slog.Logger

	mu       sync.Mutex
	cfg      Config
	ln       net.Listener
	done     chan struct{}
	wg       sync.WaitGroup
	allow    []netip.Prefix
	bound    bool
	listenOn string

	active  atomic.Int64
	total   atomic.Uint64
	blocked atomic.Uint64
	banned  atomic.Uint64
	lastErr atomic.Value // string
	// bans reports whether a source address is currently banned. It is an
	// atomic value because the ban engine is attached after construction and
	// read from the accept loop.
	bans atomic.Value // func(netip.Addr) bool
}

// New creates a manager with the forwarder stopped.
func New(log *slog.Logger) *Manager {
	m := &Manager{log: log}
	m.lastErr.Store("")
	return m
}

// SetBans attaches the ban lookup. The relay is not an HTTP request, so the
// proxy pipeline never runs for it: without this hook an address banned on 443
// could still stream through the Plex port.
func (m *Manager) SetBans(fn func(netip.Addr) bool) {
	if fn == nil {
		return
	}
	m.bans.Store(fn)
}

func (m *Manager) isBanned(addr netip.Addr) bool {
	if fn, ok := m.bans.Load().(func(netip.Addr) bool); ok && fn != nil {
		return fn(addr)
	}
	return false
}

// Apply stops the current listener and starts a new one when cfg.Enabled.
func (m *Manager) Apply(cfg Config) error {
	normalized, err := cfg.Normalize()
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	m.cfg = normalized

	if !normalized.Enabled {
		return nil
	}
	addr := net.JoinHostPort(normalized.ListenIP, strconv.Itoa(normalized.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		m.setError(err)
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	m.ln = ln
	m.done = make(chan struct{})
	m.allow = prefixesFor(normalized.Allow)
	m.bound = true
	m.listenOn = ln.Addr().String()
	m.setError(nil)
	m.log.Info("plex forwarder listening", "addr", m.listenOn, "upstream", normalized.Upstream)

	m.wg.Add(1)
	go func(done chan struct{}, ln net.Listener, cfg Config, allow []netip.Prefix) {
		defer m.wg.Done()
		m.accept(done, ln, cfg, allow)
	}(m.done, ln, normalized, m.allow)
	return nil
}

// Close stops the forwarder.
func (m *Manager) Close() {
	m.mu.Lock()
	m.stopLocked()
	m.mu.Unlock()
}

// Config returns the active configuration.
func (m *Manager) Config() Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg
}

// Status returns the configuration with live counters.
func (m *Manager) Status() Status {
	m.mu.Lock()
	cfg, bound, addr := m.cfg, m.bound, m.listenOn
	m.mu.Unlock()
	last := ""
	if v, ok := m.lastErr.Load().(string); ok {
		last = v
	}
	return Status{
		Config: cfg, Bound: bound, ListenAddr: addr,
		Active: m.active.Load(), Total: m.total.Load(), Blocked: m.blocked.Load(),
		Banned: m.banned.Load(), LastError: last,
	}
}

func (m *Manager) stopLocked() {
	if m.done != nil {
		close(m.done)
		m.done = nil
	}
	if m.ln != nil {
		_ = m.ln.Close()
		m.ln = nil
	}
	m.bound = false
	m.listenOn = ""
	m.wg.Wait()
}

func (m *Manager) setError(err error) {
	if err == nil {
		m.lastErr.Store("")
		return
	}
	m.lastErr.Store(err.Error())
}

func (m *Manager) accept(done chan struct{}, ln net.Listener, cfg Config, allow []netip.Prefix) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			m.setError(err)
			m.log.Warn("plex accept", "err", err)
			// Back off briefly so a persistently failing listener cannot spin.
			select {
			case <-done:
				return
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		if m.active.Load() >= int64(cfg.MaxConns) {
			m.blocked.Add(1)
			_ = conn.Close()
			continue
		}
		addr, ok := remoteAddr(conn.RemoteAddr())
		if !ok {
			m.blocked.Add(1)
			_ = conn.Close()
			continue
		}
		if !allowed(allow, addr) {
			m.blocked.Add(1)
			_ = conn.Close()
			continue
		}
		if m.isBanned(addr) {
			m.banned.Add(1)
			_ = conn.Close()
			continue
		}
		m.total.Add(1)
		m.active.Add(1)
		m.wg.Add(1)
		go func(client net.Conn, cfg Config) {
			defer m.wg.Done()
			defer m.active.Add(-1)
			m.handle(client, cfg)
		}(conn, cfg)
	}
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

func (m *Manager) handle(client net.Conn, cfg Config) {
	defer client.Close()

	upstream, err := net.DialTimeout("tcp", cfg.Upstream, dialTimeout)
	if err != nil {
		m.setError(err)
		m.log.Warn("plex upstream dial failed", "upstream", cfg.Upstream, "err", err)
		return
	}
	defer upstream.Close()

	if tcp, ok := client.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
	m.relay(idleConn{Conn: client}, idleConn{Conn: upstream})
}

// relay copies in both directions and tears the pair down when either side
// finishes, which is what closes a Plex stream promptly.
func (m *Manager) relay(client, upstream net.Conn) {
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
