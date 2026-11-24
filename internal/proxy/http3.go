package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// HTTP/3 is an extra path to the same handler: quic-go terminates QUIC and
// hands the request to Server.ServeHTTP, so the WAF, gate, bans, cache and
// access log apply without a second implementation. The TCP listeners keep
// serving HTTP/1.1 and HTTP/2, and nothing changes while the flag is off.

const (
	// h3MaxIncomingStreams bounds one QUIC connection. A browser opens one
	// bidirectional stream per request; 100 is more than a page needs and keeps
	// a single client from pinning memory.
	h3MaxIncomingStreams = 100
	// h3AltSvcMaxAge is how long a client may remember the alternative. One day
	// keeps a browser on HTTP/3 across a session without pinning it after the
	// operator turns the flag off.
	h3AltSvcMaxAge = 86400
	// h3HandshakeBurst and h3HandshakeWindow bound connection attempts from one
	// source address before its handshake is verified. A QUIC Initial is cheap
	// to forge, so a flood is answered per source rather than per packet.
	h3HandshakeBurst  = 10
	h3HandshakeWindow = time.Second
	// h3LimiterEntries bounds the handshake table. Past it the stale windows
	// are pruned, and a table still full refuses a new source rather than
	// growing without limit.
	h3LimiterEntries = 4096
)

// EnableHTTP3 serves HTTP/3 on port and advertises it with Alt-Svc. Zero leaves
// it off, which is the default and the only behaviour until an operator sets
// WAFPROXY_HTTP3=1. The wanted port survives a failed bind, so the next
// promotion tries again; only the advertisement is cleared.
func (s *Server) EnableHTTP3(port int) {
	if port > 0 {
		s.h3Want.Store(int64(port))
		s.h3Port.Store(int64(port))
	}
}

// http3Port is the port Alt-Svc currently advertises: zero while no QUIC
// socket is bound.
func (s *Server) http3Port() int { return int(s.h3Port.Load()) }

// http3Want is the configured port, which is what a listener binds.
func (s *Server) http3Want() int { return int(s.h3Want.Load()) }

// setAltSvc announces the QUIC alternative on responses that arrived over TLS
// on HTTP/1.1 or HTTP/2. A request that already came over HTTP/3 needs no
// advertisement, and so does one to the plain-HTTP redirector: that client is
// about to be sent to HTTPS and cannot use h3 from there.
func (s *Server) setAltSvc(w http.ResponseWriter, r *http.Request) {
	port := s.http3Port()
	if port == 0 || r.TLS == nil || r.ProtoMajor >= 3 {
		return
	}
	w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=%d`, port, h3AltSvcMaxAge))
}

// h3TLSConfig reuses the certificate resolver of the TCP listener, so an h3
// handshake picks the same certificate for the same SNI. QUIC requires TLS 1.3
// and an h3-only ALPN; http3.Server sets that ALPN again, and the explicit
// value documents what this socket may negotiate.
func (s *Server) h3TLSConfig() *tls.Config {
	c := s.tlsConfig()
	c.NextProtos = []string{"h3"}
	c.MinVersion = tls.VersionTLS13
	return c
}

// h3QUICConfig bounds a QUIC server. 0-RTT stays off: a replayed early request
// would reach the pipeline before the handshake binds the client to an address,
// which is exactly the property the source policy depends on.
func (s *Server) h3QUICConfig() *quic.Config {
	cfg := &quic.Config{
		Allow0RTT:            false,
		MaxIncomingStreams:   h3MaxIncomingStreams,
		HandshakeIdleTimeout: 5 * time.Second,
	}
	cfg.GetConfigForClient = func(info *quic.ClientInfo) (*quic.Config, error) {
		// An address that no token has verified is a candidate for spoofing,
		// so one source may start only a bounded number of handshakes a second.
		if !info.AddrVerified && !s.h3Rate.allow(info.RemoteAddr) {
			return nil, errors.New("http/3 handshake rate limited")
		}
		return cfg, nil
	}
	return cfg
}

// h3Attempts is a per-source fixed window for connection attempts. It is a
// plain guarded map: at handshake rate the lock is free, and a QUIC connection
// does not exist yet when the decision is made.
type h3Attempts struct {
	mu   sync.Mutex
	seen map[string]*h3Window
}

type h3Window struct {
	start time.Time
	n     int
}

// allow reports whether this attempt fits in the source's window.
func (a *h3Attempts) allow(addr net.Addr) bool {
	if addr == nil {
		return true
	}
	src, _, err := net.SplitHostPort(addr.String())
	if err != nil || src == "" {
		return true
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.seen == nil {
		a.seen = map[string]*h3Window{}
	}
	w := a.seen[src]
	if w == nil || now.Sub(w.start) >= h3HandshakeWindow {
		if w == nil && len(a.seen) >= h3LimiterEntries {
			a.prune(now)
			if len(a.seen) >= h3LimiterEntries {
				return false
			}
		}
		w = &h3Window{start: now}
		a.seen[src] = w
	}
	w.n++
	return w.n <= h3HandshakeBurst
}

// prune drops windows that closed at least a full window ago.
func (a *h3Attempts) prune(now time.Time) {
	for src, w := range a.seen {
		if now.Sub(w.start) >= 2*h3HandshakeWindow {
			delete(a.seen, src)
		}
	}
}

// h3Listener is the QUIC side of a bound set: one server and its socket.
type h3Listener struct {
	srv  *http3.Server
	conn net.PacketConn
}

// shutdown asks live h3 connections to finish within ctx.
func (h *h3Listener) shutdown(ctx context.Context) {
	if h == nil {
		return
	}
	_ = h.srv.Shutdown(ctx)
}

// close drops the server and the socket. It is safe after shutdown.
func (h *h3Listener) close() {
	if h == nil {
		return
	}
	_ = h.srv.Close()
	_ = h.conn.Close()
}

// listenHTTP3 binds the UDP socket beside the first TCP listener and serves the
// same handler. It runs before the TCP listeners accept, so a UDP port that is
// already taken fails the promotion with an error instead of leaving HTTP/3
// silently absent while HTTP/2 keeps working.
func (l *Listeners) listenHTTP3(port int) error {
	host, _, err := net.SplitHostPort(l.bound[0])
	if err != nil {
		host = ""
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("http/3 listen %s: %w", addr, err)
	}
	srv := &http3.Server{
		Handler:        l.s,
		TLSConfig:      l.s.h3TLSConfig(),
		QUICConfig:     l.s.h3QUICConfig(),
		MaxHeaderBytes: 32 << 10,
		Logger:         l.s.d.Log,
	}
	l.h3 = &h3Listener{srv: srv, conn: pc}
	l.s.h3Port.Store(int64(port))
	go func() {
		l.s.d.Log.Info("http/3 listening", "addr", addr)
		if err := srv.Serve(pc); err != nil && !errors.Is(err, http.ErrServerClosed) {
			l.s.d.Log.Error("http/3 listener stopped", "err", err)
		}
	}()
	if l.ctx != nil {
		go func() {
			<-l.ctx.Done()
			l.h3.close()
		}()
	}
	return nil
}
