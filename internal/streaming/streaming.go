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
	"sort"
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
	// maxPortCount bounds one service's listen range.
	maxPortCount = 16
	// newSessionRate is how many new UDP sessions one source address may start
	// per second, with newSessionBurst allowed at once.
	newSessionRate  = 10
	newSessionBurst = 30
)

// amplificationPorts are the numbers a UDP reflector is built from. A game never
// needs one, and answering on one turns this host into somebody's amplifier.
var amplificationPorts = map[int]string{
	53:    "DNS",
	123:   "NTP",
	161:   "SNMP",
	389:   "CLDAP",
	1900:  "SSDP",
	5353:  "mDNS",
	11211: "memcached",
}

// Service is one supported forwarder. A game entry seeds the form and nothing
// more: its ports are the game's published defaults, which change between
// builds, so every field stays editable.
type Service struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Group string `json:"group"`
	// Protocol is the preset's default: tcp, udp or both.
	Protocol string `json:"protocol"`
	// DefaultPort and PortCount seed the listen range; the custom card has no
	// port of its own, so its DefaultPort is 0.
	DefaultPort int `json:"default_port"`
	PortCount   int `json:"port_count"`
	// Notes is one line shown under the card.
	Notes string `json:"notes"`
}

// Groups section the catalog on the Streaming page.
const (
	GroupMedia  = "media"
	GroupGame   = "game"
	GroupCustom = "custom"
)

// Catalog lists the forwarders the gateway can offer. Adding an entry here is
// enough to get a section in the Streaming page and its own settings.
var Catalog = []Service{
	{ID: "plex", Label: "Plex", Group: GroupMedia, Protocol: "tcp", DefaultPort: 32400, PortCount: 1,
		Notes: "TLS passes through; the server trusts this host's LAN address."},
	{ID: "jellyfin", Label: "Jellyfin", Group: GroupMedia, Protocol: "tcp", DefaultPort: 8096, PortCount: 1,
		Notes: "TLS passes through; Jellyfin's known-proxies list takes this host's LAN address."},
	// Custom forwards any port on either protocol, so an application without a
	// preset does not need HAProxy beside the gateway.
	{ID: "custom", Label: "Custom TCP/UDP", Group: GroupCustom, Protocol: "tcp", DefaultPort: 0, PortCount: 1,
		Notes: "Any port and protocol; set them to match the game."},

	{ID: "minecraft-java", Label: "Minecraft (Java)", Group: GroupGame, Protocol: "tcp", DefaultPort: 25565, PortCount: 1,
		Notes: "TCP only; Bedrock is its own card."},
	{ID: "minecraft-bedrock", Label: "Minecraft (Bedrock)", Group: GroupGame, Protocol: "udp", DefaultPort: 19132, PortCount: 1,
		Notes: "IPv6 clients use 19133; add it as a second card if you need it."},
	{ID: "source", Label: "Source engine (TF2, CS, Garry's Mod)", Group: GroupGame, Protocol: "both", DefaultPort: 27015, PortCount: 1,
		Notes: "UDP carries the game; some server tools use TCP."},
	{ID: "valheim", Label: "Valheim", Group: GroupGame, Protocol: "udp", DefaultPort: 2456, PortCount: 3,
		Notes: "2456-2458 in one card, mapped 1:1 onto the server."},
	{ID: "palworld", Label: "Palworld", Group: GroupGame, Protocol: "udp", DefaultPort: 8211, PortCount: 1,
		Notes: "One UDP port for game and query."},
	{ID: "fivem", Label: "FiveM", Group: GroupGame, Protocol: "both", DefaultPort: 30120, PortCount: 1,
		Notes: "The same number on both protocols."},
	{ID: "factorio", Label: "Factorio", Group: GroupGame, Protocol: "both", DefaultPort: 34197, PortCount: 1,
		Notes: "UDP carries the game; some tools use TCP."},
	{ID: "ark", Label: "ARK: Survival Evolved", Group: GroupGame, Protocol: "udp", DefaultPort: 7777, PortCount: 2,
		Notes: "7777-7778 in one card; the query port is a separate card."},
	{ID: "ark-query", Label: "ARK query port", Group: GroupGame, Protocol: "udp", DefaultPort: 27015, PortCount: 1,
		Notes: "Only needed when clients query a separate port."},
	{ID: "rust", Label: "Rust", Group: GroupGame, Protocol: "both", DefaultPort: 28015, PortCount: 1,
		Notes: "Game traffic; RCON is a separate card."},
	{ID: "rust-rcon", Label: "Rust RCON", Group: GroupGame, Protocol: "tcp", DefaultPort: 28016, PortCount: 1,
		Notes: "TCP only, and only when RCON is enabled on the server."},
	{ID: "7dtd", Label: "7 Days to Die", Group: GroupGame, Protocol: "both", DefaultPort: 26900, PortCount: 4,
		Notes: "26900-26903; some servers use only two of them, so trim the count."},
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
	// Protocol is tcp (the default) or udp.
	Protocol string `json:"protocol"`
	// PortCount maps a listen range 1:1 onto the upstream: Port+i forwards to
	// UpstreamPort+i, so Valheim's 2456-2458 needs one card, not three.
	PortCount    int `json:"port_count"`
	UpstreamPort int `json:"upstream_port"`
	// UDP-only limits: sessions per source address, the idle window that
	// reclaims a session, and the largest datagram forwarded.
	MaxPerSource int `json:"max_per_source"`
	IdleSeconds  int `json:"idle_seconds"`
	MaxDatagram  int `json:"max_datagram"`
	// RequireAllow refuses every UDP session unless a source is on an allow
	// list. With no list attached it refuses everyone, which is safer than
	// answering anyone.
	RequireAllow bool `json:"require_allow"`
	// ListIDs are the named block/allow lists this port enforces. They are
	// resolved to their entries at apply time, so editing a list here and on
	// the Policies page is the same edit.
	ListIDs []int64 `json:"list_ids"`
}

// List is the part of a named blocklist or whitelist a forwarder enforces.
type List struct {
	ID        int64    `json:"id"`
	Name      string   `json:"name"`
	Block     bool     `json:"block"`
	Prefixes  []string `json:"prefixes"`
	Countries []string `json:"countries"`
}

// Event is a refusal or a cut stream, handed to the sink that logs it.
type Event struct {
	Service string
	Label   string
	Port    int
	Addr    netip.Addr
	// Kind is the rule the refusal is filed under: stream-ban for the ban
	// engine, stream-list when a named block/whitelist refused the source,
	// stream-allow for the port's own allow list, and stream-cap for a session
	// or source cap.
	Kind string
	// Method is the protocol that carried the refusal, TCP or UDP. Events are
	// written into the same column as an HTTP method, so logs read alike.
	Method string
	Detail string
}

// Session is one live TCP stream or UDP session as the status page lists it. A
// TCP stream's packets are the read and write chunks it moved.
type Session struct {
	Addr       string    `json:"addr"`
	Port       int       `json:"port"`
	Protocol   string    `json:"protocol"`
	BytesIn    uint64    `json:"bytes_in"`
	BytesOut   uint64    `json:"bytes_out"`
	PacketsIn  uint64    `json:"packets_in"`
	PacketsOut uint64    `json:"packets_out"`
	Started    time.Time `json:"started"`
}

// Status is the configuration plus live state for one service. Active counts
// TCP connections and ActiveSessions counts UDP sessions, because the two have
// different lifetimes and the page shows both.
type Status struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	DefaultPort int    `json:"default_port"`
	Config
	Bound          bool      `json:"bound"`
	ListenAddr     string    `json:"listen_addr"`
	UpstreamBase   string    `json:"upstream_base"`
	Active         int64     `json:"active"`
	ActiveSessions int64     `json:"active_sessions"`
	Total          uint64    `json:"total"`
	Blocked        uint64    `json:"blocked"`
	Banned         uint64    `json:"banned"`
	Dropped        uint64    `json:"dropped"`
	Oversize       uint64    `json:"oversize"`
	BytesIn        uint64    `json:"bytes_in"`
	BytesOut       uint64    `json:"bytes_out"`
	PacketsIn      uint64    `json:"packets_in"`
	PacketsOut     uint64    `json:"packets_out"`
	Refused        uint64    `json:"refused"`
	Sessions       []Session `json:"sessions"`
	LastError      string    `json:"last_error"`
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
	// positive reads a numeric setting, falling back to def when the key is
	// missing or unusable; a saved zero is not something the form can produce.
	positive := func(field string, def int) int {
		if v, err := strconv.Atoi(get(field)); err == nil && v > 0 {
			return v
		}
		return def
	}
	allow := []string{}
	for _, part := range strings.Split(get("allow"), ",") {
		if part = strings.TrimSpace(part); part != "" {
			allow = append(allow, part)
		}
	}
	lists := []int64{}
	for _, part := range strings.Split(get("lists"), ",") {
		if id, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64); err == nil && id > 0 {
			lists = append(lists, id)
		}
	}
	protocol := strings.ToLower(strings.TrimSpace(get("protocol")))
	if protocol == "" {
		// 1.60 wrote no protocol; a preset that has one seeds it.
		protocol = def.Protocol
	}
	return Config{
		Enabled:   get("enabled") == "1",
		ListenIP:  get("listen_ip"),
		Port:      positive("port", def.DefaultPort),
		Upstream:  get("upstream"),
		Allow:     allow,
		MaxConns:  positive("max_conns", DefaultMaxConns),
		Protocol:  protocol,
		PortCount: positive("port_count", def.PortCount),
		// Absent means the upstream string carries the port, which is how 1.60
		// saved it; Normalize derives the base from there.
		UpstreamPort: positive("upstream_port", 0),
		MaxPerSource: positive("max_per_source", DefaultMaxPerSource),
		IdleSeconds:  positive("idle_seconds", DefaultUDPIdleSeconds),
		MaxDatagram:  positive("max_datagram", DefaultMaxDatagram),
		RequireAllow: get("require_allow") == "1",
		ListIDs:      lists,
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

	// Normalize the allow list first: the privileged-port rule below asks
	// whether one is attached.
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

	switch c.Protocol = strings.ToLower(strings.TrimSpace(c.Protocol)); c.Protocol {
	case "":
		c.Protocol = "tcp"
	case "tcp", "udp", "both":
	default:
		return c, errors.New("protocol must be tcp, udp or both")
	}
	if c.PortCount == 0 {
		c.PortCount = 1
	}
	if c.PortCount < 1 || c.PortCount > maxPortCount {
		return c, fmt.Errorf("port_count must be between 1 and %d", maxPortCount)
	}
	if c.Port+c.PortCount-1 > 65535 {
		return c, fmt.Errorf("port range %d-%d runs past 65535", c.Port, c.Port+c.PortCount-1)
	}
	// UDP is the reflector: the denylist and the privileged-port rule apply to
	// every protocol that opens a socket on the number, and not to TCP.
	if c.Protocol != "tcp" {
		// The denylist is checked first: its reason is the one that matters for
		// 53, 123, 161 and 389, which are also privileged.
		for port := c.Port; port <= c.Port+c.PortCount-1; port++ {
			if reason, bad := amplificationPorts[port]; bad {
				return c, fmt.Errorf("port %d is an amplification port (%s): opening it over UDP turns this host into a reflector", port, reason)
			}
		}
		if c.Port < 1024 && (!c.RequireAllow || len(c.Allow) == 0) {
			return c, fmt.Errorf("port %d is below 1024: a UDP port there needs \"require an allow list\" and at least one allowed source", c.Port)
		}
	}

	host, port, err := splitHostPort(c.Upstream, def.DefaultPort)
	if err != nil {
		return c, err
	}
	if c.UpstreamPort == 0 {
		c.UpstreamPort, _ = strconv.Atoi(port)
	}
	if c.UpstreamPort < 1 || c.UpstreamPort > 65535 {
		return c, errors.New("the upstream port is not valid")
	}
	if c.UpstreamPort+c.PortCount-1 > 65535 {
		return c, fmt.Errorf("upstream port range %d-%d runs past 65535", c.UpstreamPort, c.UpstreamPort+c.PortCount-1)
	}
	c.Upstream = net.JoinHostPort(host, strconv.Itoa(c.UpstreamPort))

	if c.MaxPerSource == 0 {
		c.MaxPerSource = DefaultMaxPerSource
	}
	if c.MaxPerSource < 1 || c.MaxPerSource > 4096 {
		return c, errors.New("max_per_source must be between 1 and 4096")
	}
	if c.IdleSeconds == 0 {
		c.IdleSeconds = DefaultUDPIdleSeconds
	}
	if c.IdleSeconds < 10 || c.IdleSeconds > 3600 {
		return c, errors.New("idle_seconds must be between 10 and 3600")
	}
	if c.MaxDatagram == 0 {
		c.MaxDatagram = DefaultMaxDatagram
	}
	if c.MaxDatagram < 576 || c.MaxDatagram > maxDatagramCeiling {
		return c, fmt.Errorf("max_datagram must be between 576 and %d", maxDatagramCeiling)
	}

	ids := make([]int64, 0, len(c.ListIDs))
	seen := make(map[int64]bool, len(c.ListIDs))
	for _, id := range c.ListIDs {
		if id > 0 && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	c.ListIDs = ids
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

// namedPrefix keeps the list an address matched, so the refusal can name it.
type namedPrefix struct {
	prefix netip.Prefix
	name   string
}

// sourcePolicy is the compiled set of sources a forwarder accepts. It mirrors
// the HTTP pipeline's rules: a blocklist is checked first and always wins, a
// whitelist makes the port exclusive, and the port's own allow list is added
// to the whitelist rather than overriding it.
type sourcePolicy struct {
	allow        []netip.Prefix
	allowList    []namedPrefix
	allowCountry map[string]string // country code -> whitelist name
	denyList     []namedPrefix
	denyCountry  map[string]string
	allowNames   []string
}

// compileSources resolves the selected list ids against the lists the console
// saved. An id that no longer resolves is skipped, exactly as the policy engine
// skips a dangling reference.
func compileSources(cfg Config, lists []List) sourcePolicy {
	p := sourcePolicy{
		allow:        prefixesFor(cfg.Allow),
		allowCountry: map[string]string{},
		denyCountry:  map[string]string{},
	}
	byID := make(map[int64]List, len(lists))
	for _, l := range lists {
		byID[l.ID] = l
	}
	for _, id := range cfg.ListIDs {
		l, ok := byID[id]
		if !ok {
			continue
		}
		if l.Block {
			for _, raw := range l.Prefixes {
				if pr, err := netip.ParsePrefix(raw); err == nil {
					p.denyList = append(p.denyList, namedPrefix{prefix: pr, name: l.Name})
				}
			}
			for _, c := range l.Countries {
				p.denyCountry[c] = l.Name
			}
			continue
		}
		p.allowNames = append(p.allowNames, l.Name)
		for _, raw := range l.Prefixes {
			if pr, err := netip.ParsePrefix(raw); err == nil {
				p.allowList = append(p.allowList, namedPrefix{prefix: pr, name: l.Name})
			}
		}
		for _, c := range l.Countries {
			p.allowCountry[c] = l.Name
		}
	}
	return p
}

// openToAnyone reports whether nothing restricts the port: no allow list entry,
// no named whitelist and no whitelisted country.
func (p sourcePolicy) openToAnyone() bool {
	return len(p.allow) == 0 && len(p.allowList) == 0 && len(p.allowCountry) == 0
}

// verdict reports whether a source may connect. A non-empty kind means the
// connection is refused; list names the blocklist or whitelist responsible, so
// the event row says which list to edit.
func (p sourcePolicy) verdict(addr netip.Addr, country string) (kind, list, detail string) {
	for _, np := range p.denyList {
		if np.prefix.Contains(addr) {
			return "stream-list", np.name, "address is on the \"" + np.name + "\" blocklist"
		}
	}
	if country != "" {
		if name, ok := p.denyCountry[country]; ok {
			return "stream-list", name, "country " + country + " is on the \"" + name + "\" blocklist"
		}
	}

	if p.openToAnyone() {
		return "", "", ""
	}
	for _, pr := range p.allow {
		if pr.Contains(addr) {
			return "", "", ""
		}
	}
	for _, np := range p.allowList {
		if np.prefix.Contains(addr) {
			return "", "", ""
		}
	}
	if country != "" {
		if _, ok := p.allowCountry[country]; ok {
			return "", "", ""
		}
	}
	if len(p.allowNames) > 0 {
		joined := strings.Join(p.allowNames, ", ")
		if len(p.allowNames) == 1 {
			return "stream-list", joined, "address is not on the \"" + joined + "\" whitelist"
		}
		return "stream-list", joined, "address is on none of this port's whitelists (" + joined + ")"
	}
	return "stream-allow", "", "address is not on the forwarder's allow list"
}

// Manager owns one listener per enabled service. Apply rebinds a single service
// without touching the others.
type Manager struct {
	log *slog.Logger

	mu       sync.Mutex
	services map[string]*runtime

	bans    atomic.Value // func(netip.Addr) bool
	events  atomic.Value // func(Event)
	lists   atomic.Value // map[int64]List
	country atomic.Value // func(netip.Addr) string

	refusals *throttle
	rates    *rateLimiter
	now      func() time.Time
}

// runtime is the live state of one service: the TCP listeners of its range, its
// UDP sockets, and the counters both report through.
type runtime struct {
	def Service
	cfg Config
	// src is swapped when a list is edited, so accept() reads it without a lock
	// and an edit never races a connection.
	src       atomic.Pointer[sourcePolicy]
	listeners []*tcpListener
	done      chan struct{}
	wg        sync.WaitGroup

	connMu sync.Mutex
	conns  map[*relay]struct{}

	udp *udpRuntime

	active  atomic.Int64
	total   atomic.Uint64
	blocked atomic.Uint64
	banned  atomic.Uint64
	dropped atomic.Uint64
	lastErr atomic.Value // string
}

// tcpListener is one bound TCP port. A range listens on N ports and forwards
// each to its own upstream port.
type tcpListener struct {
	ln       net.Listener
	port     int
	upstream string
}

// relay is one accepted pair of sockets, kept so a ban can cut a stream that is
// already running instead of only refusing new ones.
type relay struct {
	client   net.Conn
	upstream net.Conn
	addr     netip.Addr
	port     int
	started  time.Time

	bytesIn, bytesOut     atomic.Uint64
	packetsIn, packetsOut atomic.Uint64
}

// New creates a manager with no listeners.
func New(log *slog.Logger) *Manager {
	return &Manager{
		log:      log,
		services: make(map[string]*runtime),
		refusals: newThrottle(refusalWindow),
		rates:    newRateLimiter(newSessionRate, newSessionBurst),
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

// SetLists replaces the named lists forwarders resolve their ids against. Call
// Apply or RefreshSources afterwards to make the change take effect.
func (m *Manager) SetLists(lists []List) {
	byID := make(map[int64]List, len(lists))
	for _, l := range lists {
		byID[l.ID] = l
	}
	m.lists.Store(byID)
}

// SetCountryLookup attaches the GeoIP lookup a country entry needs. Without
// it, country rules simply never match, and the console says so.
func (m *Manager) SetCountryLookup(fn func(netip.Addr) string) {
	if fn != nil {
		m.country.Store(fn)
	}
}

func (m *Manager) configuredLists(ids []int64) []List {
	byID, _ := m.lists.Load().(map[int64]List)
	out := make([]List, 0, len(ids))
	for _, id := range ids {
		if l, ok := byID[id]; ok {
			out = append(out, l)
		}
	}
	return out
}

func (m *Manager) countryOf(addr netip.Addr) string {
	if fn, ok := m.country.Load().(func(netip.Addr) string); ok && fn != nil {
		return fn(addr)
	}
	return ""
}

// RefreshSources recompiles every listener's source policy after a list was
// edited. Sockets are left alone, so changing a blocklist never interrupts a
// client that is streaming.
func (m *Manager) RefreshSources() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, rt := range m.services {
		rt.setSource(compileSources(rt.cfg, m.configuredLists(rt.cfg.ListIDs)))
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
	rt.setSource(compileSources(cfg, m.configuredLists(cfg.ListIDs)))
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
		rt.setSource(compileSources(norm, m.configuredLists(norm.ListIDs)))
		// "both" needs two sockets on the same number; a failure on one leaves
		// the other serving, and the error names the protocol that failed.
		var failed []string
		if norm.Protocol != "udp" {
			if err := m.bindTCP(rt); err != nil {
				failed = append(failed, err.Error())
			}
		}
		if norm.Protocol != "tcp" {
			u, err := m.bindUDP(rt)
			if err != nil {
				failed = append(failed, err.Error())
			} else {
				rt.udp = u
				m.log.Info("streaming udp forwarder listening", "service", id, "addr", u.listenAddr(), "upstream", norm.Upstream,
					"sessions", norm.MaxConns, "max_per_source", norm.MaxPerSource, "allow_list_entries", len(norm.Allow), "named_lists", len(norm.ListIDs))
			}
		}
		if len(failed) > 0 {
			listenErr = errors.New(strings.Join(failed, "; "))
			rt.lastErr.Store(listenErr.Error())
		}
	}
	m.mu.Unlock()

	for _, l := range rt.listeners {
		rt.wg.Add(1)
		go m.accept(rt, l)
	}
	if rt.udp != nil {
		rt.udp.start()
	}
	return listenErr
}

// bindTCP binds one port per entry in the range. A range is one logical
// service, so a failure on any port releases the ones already bound.
func (m *Manager) bindTCP(rt *runtime) error {
	cfg := rt.cfg
	host, _, err := net.SplitHostPort(cfg.Upstream)
	if err != nil {
		return fmt.Errorf("upstream %q: %w", cfg.Upstream, err)
	}
	for i := 0; i < cfg.PortCount; i++ {
		addr := net.JoinHostPort(cfg.ListenIP, strconv.Itoa(cfg.Port+i))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, l := range rt.listeners {
				_ = l.ln.Close()
			}
			rt.listeners = nil
			return fmt.Errorf("listen on %s/tcp: %w", addr, err)
		}
		rt.listeners = append(rt.listeners, &tcpListener{
			ln:       ln,
			port:     cfg.Port + i,
			upstream: net.JoinHostPort(host, strconv.Itoa(cfg.UpstreamPort+i)),
		})
	}
	rt.done = make(chan struct{})
	m.log.Info("streaming forwarder listening", "service", rt.def.ID, "protocol", cfg.Protocol,
		"addr", describeRange(rt.listeners[0].ln.Addr().String(), cfg.Port, cfg.PortCount),
		"upstream", cfg.Upstream, "allow_list_entries", len(cfg.Allow), "named_lists", len(cfg.ListIDs))
	return nil
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
	// The UDP sessions go before the listen sockets, so a demotion leaves the
	// ports free for the node that takes over.
	if rt.udp != nil {
		rt.udp.close()
	}
	for _, l := range rt.listeners {
		_ = l.ln.Close()
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
			st.Sessions = []Session{}
			out = append(out, st)
			continue
		}
		st.Config = rt.cfg
		st.UpstreamBase = rt.cfg.Upstream
		st.Active = rt.active.Load()
		st.Total = rt.total.Load()
		st.Blocked = rt.blocked.Load()
		st.Banned = rt.banned.Load()
		st.Dropped = rt.dropped.Load()
		if v, ok := rt.lastErr.Load().(string); ok {
			st.LastError = v
		}

		sessions := make([]Session, 0, len(rt.conns))
		rt.connMu.Lock()
		for r := range rt.conns {
			in, out := r.bytesIn.Load(), r.bytesOut.Load()
			pktsIn, pktsOut := r.packetsIn.Load(), r.packetsOut.Load()
			st.BytesIn += in
			st.BytesOut += out
			st.PacketsIn += pktsIn
			st.PacketsOut += pktsOut
			sessions = append(sessions, Session{
				Addr: r.addr.String(), Port: r.port, Protocol: "TCP",
				BytesIn: in, BytesOut: out, PacketsIn: pktsIn, PacketsOut: pktsOut,
				Started: r.started,
			})
		}
		rt.connMu.Unlock()

		tcpBound, udpBound := len(rt.listeners) > 0, rt.udp != nil
		switch rt.cfg.Protocol {
		case "udp":
			st.Bound = udpBound
		case "both":
			// Both sockets were asked for, so one alone is a partial start.
			st.Bound = tcpBound && udpBound
		default:
			st.Bound = tcpBound
		}
		switch {
		case tcpBound && udpBound:
			st.ListenAddr = describeRange(rt.listeners[0].ln.Addr().String(), rt.cfg.Port, rt.cfg.PortCount) + " tcp+udp"
		case tcpBound:
			st.ListenAddr = describeRange(rt.listeners[0].ln.Addr().String(), rt.cfg.Port, rt.cfg.PortCount)
		case udpBound:
			st.ListenAddr = rt.udp.listenAddr()
		}

		if u := rt.udp; u != nil {
			st.ActiveSessions = u.active.Load()
			st.Total += u.total.Load()
			st.Blocked += u.blocked.Load()
			st.Banned += u.banned.Load()
			st.Dropped += u.dropped.Load()
			st.Oversize = u.oversize.Load()
			st.BytesIn += u.bytesIn.Load()
			st.BytesOut += u.bytesOut.Load()
			st.PacketsIn += u.pktsIn.Load()
			st.PacketsOut += u.pktsOut.Load()
			sessions = append(sessions, u.sessions()...)
		}
		st.Refused = st.Blocked + st.Banned
		st.Sessions = topSessions(sessions)
		out = append(out, st)
	}
	return out
}

// maxStatusSessions caps the live session list the page renders.
const maxStatusSessions = 50

// topSessions keeps the busiest sessions, so the page can show top talkers
// without a second call.
func topSessions(all []Session) []Session {
	sort.Slice(all, func(i, j int) bool {
		return all[i].BytesIn+all[i].BytesOut > all[j].BytesIn+all[j].BytesOut
	})
	if len(all) > maxStatusSessions {
		all = all[:maxStatusSessions]
	}
	return all
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
		s  *udpSession
	}
	var doomed []victim

	m.mu.Lock()
	for _, rt := range m.services {
		rt.connMu.Lock()
		for r := range rt.conns {
			if match(r.addr) {
				doomed = append(doomed, victim{rt: rt, r: r})
			}
		}
		rt.connMu.Unlock()
		if rt.udp != nil {
			for _, s := range rt.udp.matching(match) {
				doomed = append(doomed, victim{rt: rt, s: s})
			}
		}
	}
	m.mu.Unlock()

	for _, v := range doomed {
		if v.s != nil {
			v.rt.udp.drop(v.s)
			v.rt.udp.dropped.Add(1)
			m.emit(Event{Service: v.rt.def.ID, Label: v.rt.def.Label, Method: "UDP", Port: v.s.key.port,
				Addr: v.s.addr, Kind: "stream-ban", Detail: detail})
			continue
		}
		// Closing both ends unblocks the two copy goroutines immediately.
		_ = v.r.client.Close()
		_ = v.r.upstream.Close()
		v.rt.dropped.Add(1)
		m.emit(Event{Service: v.rt.def.ID, Label: v.rt.def.Label, Method: "TCP", Port: v.r.port, Addr: v.r.addr, Kind: "stream-ban", Detail: detail})
	}
	return len(doomed)
}

func (m *Manager) accept(rt *runtime, l *tcpListener) {
	defer rt.wg.Done()
	for {
		conn, err := l.ln.Accept()
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
		if !ok {
			rt.blocked.Add(1)
			_ = conn.Close()
			continue
		}
		src := rt.source()
		if kind, list, detail := src.verdict(addr, m.countryOf(addr)); kind != "" {
			rt.blocked.Add(1)
			_ = conn.Close()
			m.refuseAt(rt, l.port, "TCP", addr, kind, detail, list)
			continue
		}
		if m.isBanned(addr) {
			_ = conn.Close()
			// Emit before counting so the status counter never runs ahead of
			// the event that describes the refusal.
			m.refuseAt(rt, l.port, "TCP", addr, "stream-ban", fmt.Sprintf("banned source refused on the %s port", rt.def.Label), "")
			rt.banned.Add(1)
			continue
		}
		rt.total.Add(1)
		rt.active.Add(1)
		rt.wg.Add(1)
		go func(client net.Conn) {
			defer rt.wg.Done()
			defer rt.active.Add(-1)
			m.handle(rt, l, client, addr)
		}(conn)
	}
}

// refuseAt reports a refusal on one protocol and listen port: a range has a
// socket per port, so the event names the port that was actually hit.
func (m *Manager) refuseAt(rt *runtime, port int, method string, addr netip.Addr, kind, detail, list string) {
	emit, suppressed := m.refusals.allow(rt.def.ID, addr, m.now())
	if !emit {
		return
	}
	if suppressed > 0 {
		detail += fmt.Sprintf(" (%d more attempts suppressed)", suppressed)
	}
	if list != "" {
		detail += " [" + list + "]"
	}
	m.emit(Event{Service: rt.def.ID, Label: rt.def.Label, Method: method, Port: port, Addr: addr, Kind: kind, Detail: detail})
}

func (m *Manager) handle(rt *runtime, l *tcpListener, client net.Conn, addr netip.Addr) {
	defer client.Close()

	upstream, err := net.DialTimeout("tcp", l.upstream, dialTimeout)
	if err != nil {
		rt.lastErr.Store(err.Error())
		m.log.Warn("streaming upstream dial failed", "service", rt.def.ID, "upstream", l.upstream, "err", err)
		return
	}
	defer upstream.Close()

	// Track before checking the ban: a ban that lands from here on finds the
	// relay in conns and cuts it, and one that landed during the dial is
	// caught by the check itself.
	r := &relay{client: client, upstream: upstream, addr: addr, port: l.port, started: time.Now()}
	rt.track(r)
	defer rt.untrack(r)

	if m.isBanned(addr) {
		rt.dropped.Add(1)
		m.emit(Event{Service: rt.def.ID, Label: rt.def.Label, Method: "TCP", Port: l.port, Addr: addr, Kind: "stream-ban",
			Detail: fmt.Sprintf("stream closed by active ban on the %s port", rt.def.Label)})
		return
	}

	if tcp, ok := client.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
	relayCopy(r)
}

func (rt *runtime) setSource(p sourcePolicy) { rt.src.Store(&p) }

func (rt *runtime) source() sourcePolicy {
	if p := rt.src.Load(); p != nil {
		return *p
	}
	return sourcePolicy{}
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
// finishes, which is what closes a stream promptly. Reads are counted on the
// socket they drain, so bytes in are client-to-server and bytes out the reverse.
func relayCopy(r *relay) {
	client := idleConn{Conn: r.client, bytes: &r.bytesIn, packets: &r.packetsIn}
	upstream := idleConn{Conn: r.upstream, bytes: &r.bytesOut, packets: &r.packetsOut}
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
// eventually reclaimed while a long stream is never cut in the middle. It also
// counts what it drains, which is what the status page reports.
type idleConn struct {
	net.Conn
	bytes   *atomic.Uint64
	packets *atomic.Uint64
}

func (c idleConn) Read(b []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(idleTimeout))
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.bytes.Add(uint64(n))
		c.packets.Add(1)
	}
	return n, err
}

func (c idleConn) Write(b []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(idleTimeout))
	return c.Conn.Write(b)
}

// describeRange names what the operator can reach: one address for a single
// port, a base-to-last range otherwise.
func describeRange(first string, base, count int) string {
	if count <= 1 {
		return first
	}
	return fmt.Sprintf("%s-%d", first, base+count-1)
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

// throttleMax bounds the refusal table. A botnet spray of distinct banned
// addresses would otherwise grow the map without limit, so once it is full the
// oldest entry is dropped; losing suppression state only costs an extra event.
const throttleMax = 4096

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
		if len(t.seen) >= throttleMax {
			t.prune(now)
		}
		if len(t.seen) >= throttleMax {
			t.evictOldest()
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

// evictOldest drops the least recently seen entry when the table is full of
// active sources.
func (t *throttle) evictOldest() {
	var oldest refusalKey
	var oldestAt time.Time
	first := true
	for k, e := range t.seen {
		if first || e.last.Before(oldestAt) {
			oldest, oldestAt, first = k, e.last, false
		}
	}
	if !first {
		delete(t.seen, oldest)
	}
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

// rateTableMax bounds the limiter's table, like the refusal throttle.
const rateTableMax = 4096

// rateLimiter is a token bucket per source address and service. Opening a
// session costs one token, so a source that keeps a normal session open never
// notices, while a loop of new sessions is cut off after the burst.
type rateLimiter struct {
	mu    sync.Mutex
	rate  float64
	burst float64
	seen  map[rateKey]*rateBucket
}

type rateKey struct {
	service string
	addr    netip.Addr
}

type rateBucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate, burst int) *rateLimiter {
	return &rateLimiter{rate: float64(rate), burst: float64(burst), seen: make(map[rateKey]*rateBucket)}
}

// allow takes one token for the key, refilling what elapsed since the last call.
// A full table means the source table is under a spoofed spray, so a new source
// is refused rather than growing the map.
func (r *rateLimiter) allow(service string, addr netip.Addr, now time.Time) bool {
	key := rateKey{service: service, addr: addr}
	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.seen[key]
	if !ok {
		if len(r.seen) >= rateTableMax {
			r.prune(now)
		}
		if len(r.seen) >= rateTableMax {
			return false
		}
		r.seen[key] = &rateBucket{tokens: r.burst - 1, last: now}
		return true
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * r.rate
		if b.tokens > r.burst {
			b.tokens = r.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// prune forgets the sources that stopped opening sessions a while ago.
func (r *rateLimiter) prune(now time.Time) {
	for k, b := range r.seen {
		if now.Sub(b.last) > 30*time.Second {
			delete(r.seen, k)
		}
	}
}
