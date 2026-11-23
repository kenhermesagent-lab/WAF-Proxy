package streaming

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultMaxPerSource caps how many sessions one client address may hold on
	// one service. Without it a spoofed source spray fills the session table.
	DefaultMaxPerSource = 8
	// DefaultUDPIdleSeconds is short because games keepalive continuously,
	// unlike a media player that may pause for half an hour.
	DefaultUDPIdleSeconds = 60
	// DefaultMaxDatagram is the largest datagram forwarded in either direction.
	DefaultMaxDatagram = 1500
	// maxDatagramCeiling bounds the buffer an operator can ask for.
	maxDatagramCeiling = 8192
	// udpSweepInterval is how often idle sessions are reclaimed.
	udpSweepInterval = 5 * time.Second
)

// sessionKey is one client session: the source address and port it sends from,
// plus the listen port it arrived on. A NAT rebinding changes the source port,
// which starts a new session; the old one expires.
type sessionKey struct {
	addr netip.AddrPort
	port int
}

// udpRuntime is the UDP half of one service. Each listen port gets one shared
// socket for every client, and each session its own connected upstream socket,
// so replies are demultiplexed by the kernel instead of by packet inspection.
type udpRuntime struct {
	def Service
	cfg Config
	m   *Manager
	rt  *runtime

	listeners []*udpListener
	done      chan struct{}
	wg        sync.WaitGroup

	closeOnce sync.Once

	mu        sync.Mutex
	closed    bool
	sess      map[sessionKey]*udpSession
	perSource map[netip.Addr]int

	active   atomic.Int64
	total    atomic.Uint64
	blocked  atomic.Uint64
	banned   atomic.Uint64
	dropped  atomic.Uint64
	oversize atomic.Uint64
	pktsIn   atomic.Uint64
	pktsOut  atomic.Uint64
	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64

	lastErr atomic.Value // string

	sweep time.Duration
}

type udpListener struct {
	pc     *net.UDPConn
	port   int
	upIP   net.IP
	upPort int
}

type udpSession struct {
	key      sessionKey
	addr     netip.Addr // key.addr without the IPv4-mapped form, as the caps count it
	upstream *net.UDPConn
	lastSeen atomic.Int64 // unix nanos
	once     sync.Once
}

// bindUDP creates one socket per port in the configured range and resolves the
// upstream address once, so the packet path never waits on DNS.
func (m *Manager) bindUDP(rt *runtime) (*udpRuntime, error) {
	cfg := rt.cfg
	host, _, err := net.SplitHostPort(cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("upstream %q: %w", cfg.Upstream, err)
	}

	u := &udpRuntime{
		def:       rt.def,
		cfg:       cfg,
		m:         m,
		rt:        rt,
		done:      make(chan struct{}),
		sess:      make(map[sessionKey]*udpSession),
		perSource: make(map[netip.Addr]int),
		sweep:     udpSweepInterval,
	}
	u.lastErr.Store("")
	for i := 0; i < cfg.PortCount; i++ {
		listen := cfg.Port + i
		bindAddr := net.JoinHostPort(cfg.ListenIP, strconv.Itoa(listen))
		bind, err := net.ResolveUDPAddr("udp", bindAddr)
		if err != nil {
			u.close()
			return nil, fmt.Errorf("listen on %s/udp: %w", bindAddr, err)
		}
		pc, err := net.ListenUDP("udp", bind)
		if err != nil {
			u.close()
			return nil, fmt.Errorf("listen on %s/udp: %w", bindAddr, err)
		}
		upPort := cfg.UpstreamPort + i
		up, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(upPort)))
		if err != nil || up.IP == nil {
			_ = pc.Close()
			u.close()
			return nil, fmt.Errorf("upstream %s:%d is not a resolvable address", host, upPort)
		}
		u.listeners = append(u.listeners, &udpListener{pc: pc, port: listen, upIP: up.IP, upPort: upPort})
	}
	return u, nil
}

// start launches one reader per listen socket and the janitor.
func (u *udpRuntime) start() {
	for _, l := range u.listeners {
		u.wg.Add(1)
		go u.serve(l)
	}
	u.wg.Add(1)
	go u.janitor()
}

func (u *udpRuntime) serve(l *udpListener) {
	defer u.wg.Done()
	// One byte over the cap tells an oversized datagram apart from one that
	// exactly fills it; the oversized one is dropped, never truncated.
	buf := make([]byte, u.cfg.MaxDatagram+1)
	for {
		n, from, err := l.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-u.done:
				return
			default:
			}
			u.lastErr.Store(err.Error())
			u.m.log.Warn("streaming udp read", "service", u.def.ID, "err", err)
			// Back off briefly so a persistently failing socket cannot spin.
			time.Sleep(50 * time.Millisecond)
			continue
		}
		u.handle(l, from, buf[:n])
	}
}

func (u *udpRuntime) handle(l *udpListener, from netip.AddrPort, payload []byte) {
	if len(payload) > u.cfg.MaxDatagram {
		u.oversize.Add(1)
		return
	}
	addr := from.Addr().Unmap()
	// The ban map is checked on every datagram, so a ban cuts live traffic
	// instead of only refusing new sessions.
	if u.m.isBanned(addr) {
		u.banned.Add(1)
		u.cutSource(addr)
		u.m.refuseAt(u.rt, l.port, "UDP", addr, "stream-ban",
			fmt.Sprintf("banned source dropped on the %s UDP port", u.def.Label), "")
		return
	}

	key := sessionKey{addr: from, port: l.port}
	s := u.session(key)
	if s == nil {
		var ok bool
		if s, ok = u.open(l, from, addr); !ok {
			return
		}
	}

	s.lastSeen.Store(time.Now().UnixNano())
	n, err := s.upstream.Write(payload)
	if err != nil {
		// A session the janitor closed under us: the next datagram starts a new one.
		u.drop(s)
		return
	}
	u.pktsIn.Add(1)
	u.bytesIn.Add(uint64(n))
}

func (u *udpRuntime) session(key sessionKey) *udpSession {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.sess[key]
}

// open admits a new session after the source policy, the ban list and the caps
// have agreed. A refusal is reported with the listen port that was hit.
func (u *udpRuntime) open(l *udpListener, from netip.AddrPort, addr netip.Addr) (*udpSession, bool) {
	if kind, list, detail := u.rt.source().verdict(addr, u.m.countryOf(addr)); kind != "" {
		u.blocked.Add(1)
		u.m.refuseAt(u.rt, l.port, "UDP", addr, kind, detail, list)
		return nil, false
	}

	key := sessionKey{addr: from, port: l.port}
	u.mu.Lock()
	if s, ok := u.sess[key]; ok {
		u.mu.Unlock()
		return s, true
	}
	if u.closed {
		u.mu.Unlock()
		return nil, false
	}
	reason := ""
	if u.active.Load() >= int64(u.cfg.MaxConns) {
		reason = fmt.Sprintf("the service reached its %d session cap", u.cfg.MaxConns)
	} else if u.perSource[addr] >= u.cfg.MaxPerSource {
		reason = fmt.Sprintf("more than %d sessions from one address", u.cfg.MaxPerSource)
	}
	if reason != "" {
		u.mu.Unlock()
		u.blocked.Add(1)
		// The event sink may write a row, so it runs without the session lock.
		u.m.refuseAt(u.rt, l.port, "UDP", addr, "stream-cap", reason, "")
		return nil, false
	}

	up, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: l.upIP, Port: l.upPort})
	if err != nil {
		u.mu.Unlock()
		u.lastErr.Store(err.Error())
		u.m.log.Warn("streaming udp upstream dial failed", "service", u.def.ID, "upstream", u.cfg.Upstream, "err", err)
		return nil, false
	}
	s := &udpSession{key: key, addr: addr, upstream: up}
	s.lastSeen.Store(time.Now().UnixNano())
	u.sess[key] = s
	u.perSource[addr]++
	u.active.Add(1)
	u.total.Add(1)
	// Add under the lock: close() sets closed under it, so no WaitGroup Add can
	// race the Wait that close performs.
	u.wg.Add(1)
	u.mu.Unlock()

	go u.replies(l, s)
	return s, true
}

// replies forwards what the game server sends back to the client that owns the
// session. The socket is connected, so a datagram from any other host is
// dropped by the kernel and never reaches a client.
func (u *udpRuntime) replies(l *udpListener, s *udpSession) {
	defer u.wg.Done()
	defer u.drop(s)
	buf := make([]byte, u.cfg.MaxDatagram+1)
	for {
		n, err := s.upstream.Read(buf)
		if err != nil {
			return
		}
		if n > u.cfg.MaxDatagram {
			u.oversize.Add(1)
			continue
		}
		s.lastSeen.Store(time.Now().UnixNano())
		written, err := l.pc.WriteToUDPAddrPort(buf[:n], s.key.addr)
		if err != nil {
			return
		}
		u.pktsOut.Add(1)
		u.bytesOut.Add(uint64(written))
	}
}

func (u *udpRuntime) drop(s *udpSession) {
	s.once.Do(func() {
		_ = s.upstream.Close()
		u.mu.Lock()
		delete(u.sess, s.key)
		if n := u.perSource[s.addr] - 1; n > 0 {
			u.perSource[s.addr] = n
		} else {
			delete(u.perSource, s.addr)
		}
		u.mu.Unlock()
		u.active.Add(-1)
	})
}

// cutSource closes every session the address owns, counting each cut. It is
// how a datagram from a source banned mid-session stops immediately.
func (u *udpRuntime) cutSource(addr netip.Addr) {
	for _, s := range u.matching(func(a netip.Addr) bool { return a == addr }) {
		u.drop(s)
		u.dropped.Add(1)
	}
}

func (u *udpRuntime) matching(match func(netip.Addr) bool) []*udpSession {
	u.mu.Lock()
	defer u.mu.Unlock()
	var out []*udpSession
	for _, s := range u.sess {
		if match(s.addr) {
			out = append(out, s)
		}
	}
	return out
}

func (u *udpRuntime) janitor() {
	defer u.wg.Done()
	t := time.NewTicker(u.sweep)
	defer t.Stop()
	for {
		select {
		case <-u.done:
			return
		case <-t.C:
			u.sweepIdle(time.Now())
		}
	}
}

// sweepIdle closes the sessions that have been silent past the idle window.
func (u *udpRuntime) sweepIdle(now time.Time) {
	limit := now.Add(-time.Duration(u.cfg.IdleSeconds) * time.Second).UnixNano()
	u.mu.Lock()
	var expired []*udpSession
	for _, s := range u.sess {
		if s.lastSeen.Load() < limit {
			expired = append(expired, s)
		}
	}
	u.mu.Unlock()
	for _, s := range expired {
		u.drop(s)
	}
}

// close closes the sessions first and the listen sockets second, so the ports
// are free for the other node the moment a demotion returns.
func (u *udpRuntime) close() {
	u.closeOnce.Do(func() {
		u.mu.Lock()
		u.closed = true
		doomed := make([]*udpSession, 0, len(u.sess))
		for _, s := range u.sess {
			doomed = append(doomed, s)
		}
		u.mu.Unlock()
		close(u.done)

		for _, s := range doomed {
			u.drop(s)
		}
		for _, l := range u.listeners {
			_ = l.pc.Close()
		}
		u.wg.Wait()
	})
}

// listenAddr describes what the operator can reach, e.g. 10.0.0.5:2456-2458.
func (u *udpRuntime) listenAddr() string {
	if len(u.listeners) == 0 {
		return ""
	}
	first := u.listeners[0]
	if len(u.listeners) == 1 {
		return first.pc.LocalAddr().String()
	}
	return fmt.Sprintf("%s-%d", first.pc.LocalAddr().String(), u.listeners[len(u.listeners)-1].port)
}
