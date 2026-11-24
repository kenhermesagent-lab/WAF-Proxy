package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// Upstream pool sizing. The idle cap belongs to one transport, and a transport
// serves one upstream address, so a busy backend cannot take another's slots.
const (
	defaultUpstreamIdleConns = 64
	// maxIdleUpstreamConns is a pool's total idle budget and the highest per-host
	// value a site may ask for.
	maxIdleUpstreamConns = 256
	idleUpstreamTimeout  = 90 * time.Second

	// dnsTTL is how long a resolved host is reused; dnsStale is how long the
	// last good answer is still dialled after the resolver starts failing.
	dnsTTL   = 30 * time.Second
	dnsStale = 5 * time.Minute
)

// transportKey identifies one upstream connection pool: the same address with
// a different idle size is a different pool.
type transportKey struct {
	addr        string // scheme://host:port
	idlePerHost int
}

// transportPool keeps one http.Transport per upstream address across reloads.
// A route holds a reference while it is live: an unchanged upstream keeps its
// warm connections, a removed one closes its idle ones, and a changed one gets
// a new pool while the old one finishes the requests already in flight.
type transportPool struct {
	mu      sync.Mutex
	entries map[transportKey]*transportEntry
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	// shared answers a request whose upstream is not on its context. The data
	// path always names one, so this only keeps the round trip total.
	shared *http.Transport
}

type transportEntry struct {
	t   *http.Transport
	ref int
}

func newTransportPool() *transportPool {
	p := &transportPool{entries: map[transportKey]*transportEntry{}}
	p.dial = newDNSCache().dialContext
	p.shared = p.newTransport(transportKey{})
	return p
}

func (p *transportPool) newTransport(k transportKey) *http.Transport {
	idle := k.idlePerHost
	if idle <= 0 {
		idle = defaultUpstreamIdleConns
	}
	// No Proxy field: an HTTP_PROXY in the service environment must never carry
	// customer traffic through a third party.
	return &http.Transport{
		DialContext:           p.dial,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          maxIdleUpstreamConns,
		MaxIdleConnsPerHost:   idle,
		IdleConnTimeout:       idleUpstreamTimeout,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// acquire returns the pool for k and counts the caller as one of its users.
func (p *transportPool) acquire(k transportKey) *http.Transport {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[k]
	if !ok {
		e = &transportEntry{t: p.newTransport(k)}
		p.entries[k] = e
	}
	e.ref++
	return e.t
}

// release drops a user. The last one closes the pool's idle connections; a
// request already using one of them still finishes.
func (p *transportPool) release(k transportKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[k]
	if !ok {
		return
	}
	e.ref--
	if e.ref > 0 {
		return
	}
	delete(p.entries, k)
	e.t.CloseIdleConnections()
}

// upstreamTransport sends a request through the pool its upstream owns. The
// handler already put that upstream on the request context.
type upstreamTransport struct{ def http.RoundTripper }

func (t upstreamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if up, ok := req.Context().Value(ctxUpstream).(*upstream); ok && up.transport != nil {
		return up.transport.RoundTrip(req)
	}
	return t.def.RoundTrip(req)
}

// dnsCache resolves a host once per TTL, with one lookup at a time per host.
// When the resolver fails it keeps dialling the last good answer for a bounded
// window, so a resolver blip does not take every upstream down with it.
type dnsCache struct {
	resolve func(ctx context.Context, host string) ([]string, error)
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	now     func() time.Time
	ttl     time.Duration
	stale   time.Duration

	mu    sync.Mutex
	hosts map[string]*dnsEntry
}

type dnsEntry struct {
	// mu serialises lookups for this host: the second caller finds the first
	// caller's fresh answer instead of asking the resolver again.
	mu       sync.Mutex
	addrs    []string
	expires  time.Time
	lastGood time.Time
}

func newDNSCache() *dnsCache {
	d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return &dnsCache{
		resolve: net.DefaultResolver.LookupHost,
		dial:    d.DialContext,
		now:     time.Now,
		ttl:     dnsTTL,
		stale:   dnsStale,
		hosts:   map[string]*dnsEntry{},
	}
}

func (c *dnsCache) entry(host string) *dnsEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.hosts[host]
	if !ok {
		e = &dnsEntry{}
		c.hosts[host] = e
	}
	return e
}

// lookup answers from the cache while the addresses are fresh, and from the
// last good answer while the resolver is failing inside the stale window.
func (c *dnsCache) lookup(ctx context.Context, host string) ([]string, error) {
	e := c.entry(host)
	e.mu.Lock()
	defer e.mu.Unlock()
	now := c.now()
	if len(e.addrs) > 0 && now.Before(e.expires) {
		return e.addrs, nil
	}
	addrs, err := c.resolve(ctx, host)
	if err != nil {
		if len(e.addrs) > 0 && now.Sub(e.lastGood) <= c.stale {
			return e.addrs, nil
		}
		return nil, err
	}
	e.addrs, e.expires, e.lastGood = addrs, now.Add(c.ttl), now
	return addrs, nil
}

// dialContext dials through the cache, so a burst of connections costs one
// lookup rather than one per connection. The cached answers are walked in order
// within each family and both families are dialled at once: that is the
// fallback net.Dialer does itself, so a broken IPv6 route does not cost an IPv4
// request its full dial timeout.
func (c *dnsCache) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) != nil {
		return c.dial(ctx, network, addr)
	}
	addrs, err := c.lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	var v4, v6 []string
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() == nil {
			v6 = append(v6, a)
		} else {
			v4 = append(v4, a)
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type attempt struct {
		conn net.Conn
		err  error
	}
	ch := make(chan attempt, 2)
	launched := 0
	for _, list := range [][]string{v4, v6} {
		if len(list) == 0 {
			continue
		}
		launched++
		go func(list []string) {
			var lastErr error
			for _, a := range list {
				conn, err := c.dial(ctx, network, net.JoinHostPort(a, port))
				if err == nil {
					ch <- attempt{conn: conn}
					return
				}
				lastErr = err
				if ctx.Err() != nil {
					break
				}
			}
			ch <- attempt{err: lastErr}
		}(list)
	}
	if launched == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses", host)
	}
	var conn net.Conn
	var lastErr error
	for i := 0; i < launched; i++ {
		r := <-ch
		switch {
		case r.err != nil:
			lastErr = r.err
		case conn == nil:
			conn = r.conn
			cancel() // the other family is no longer wanted
		default:
			_ = r.conn.Close()
		}
	}
	if conn != nil {
		return conn, nil
	}
	return nil, lastErr
}
