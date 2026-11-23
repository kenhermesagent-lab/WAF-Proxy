// Package clientip resolves the address a request really came from, honouring
// an optional trusted-proxy allowlist.
//
// Nothing is trusted by default, which is Caddy's trusted_proxies model: the
// direct peer is the client and forwarding headers are ignored, so a client
// cannot claim an address the access lists, the ban engine or the audit log
// would otherwise believe. Only a peer inside the configured prefixes may name
// the client, and then only through X-Forwarded-For.
package clientip

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
)

// Resolver holds the proxy prefixes that may set the client address.
type Resolver struct {
	trusted []netip.Prefix
	// cdn trusts Cloudflare's CF-Connecting-IP from a trusted peer. It is off
	// until a tunnel is enabled, so a loopback proxy cannot spoof it otherwise.
	cdn atomic.Bool
}

// SetCDN enables or disables trusting CF-Connecting-IP from a trusted peer.
func (r *Resolver) SetCDN(on bool) {
	if r != nil {
		r.cdn.Store(on)
	}
}

// New parses CIDR prefixes or single addresses. An empty list trusts nothing.
func New(entries []string) (*Resolver, error) {
	r := &Resolver{}
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.ContainsRune(raw, '/') {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("trusted proxy %q: %w", raw, err)
			}
			r.trusted = append(r.trusted, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", raw, err)
		}
		a = a.Unmap()
		r.trusted = append(r.trusted, netip.PrefixFrom(a, a.BitLen()))
	}
	return r, nil
}

// Trusts reports whether addr is a configured proxy.
func (r *Resolver) Trusts(addr netip.Addr) bool {
	if r == nil {
		return false
	}
	for _, p := range r.trusted {
		if p.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}

// Resolve returns the client address. When the peer is not a trusted proxy the
// peer is the client, whatever the headers say. When it is, the right-most
// X-Forwarded-For entry that is itself not a trusted proxy wins, so a chain of
// proxies collapses to the last hop this deployment did not authorise.
func (r *Resolver) Resolve(peer netip.Addr, forwarded []string) netip.Addr {
	peer = peer.Unmap()
	if !r.Trusts(peer) {
		return peer
	}
	hops := forwardedAddrs(forwarded)
	for i := len(hops) - 1; i >= 0; i-- {
		if !r.Trusts(hops[i]) {
			return hops[i]
		}
	}
	return peer
}

// FromRequest resolves the client from a request. It reports false when the
// peer address cannot be parsed, in which case the caller keeps RemoteAddr.
func (r *Resolver) FromRequest(req *http.Request) (netip.Addr, bool) {
	peer, err := peerAddr(req.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	// Cloudflare's edge overwrites this header, and only the connector can
	// reach this listener from loopback, so it is the address the WAF must
	// filter, log and ban on while a tunnel is enabled.
	if r.cdn.Load() && r.Trusts(peer) {
		if a, err := netip.ParseAddr(strings.TrimSpace(req.Header.Get("CF-Connecting-IP"))); err == nil {
			return a.Unmap(), true
		}
	}
	return r.Resolve(peer, req.Header.Values("X-Forwarded-For")), true
}

func peerAddr(remote string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	return netip.ParseAddr(strings.Trim(host, "[]"))
}

func forwardedAddrs(values []string) []netip.Addr {
	out := make([]netip.Addr, 0, len(values))
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if a, err := netip.ParseAddr(strings.TrimSpace(part)); err == nil {
				out = append(out, a.Unmap())
			}
		}
	}
	return out
}
