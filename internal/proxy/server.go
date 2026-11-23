// Package proxy implements the TLS termination, host routing and HTTP pipeline.
package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/botguard"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/clientip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/gate"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/policy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

// CertProvider resolves certificates for SNI names.
type CertProvider interface {
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
}

// CertByIDProvider resolves the certificate a site named explicitly.
type CertByIDProvider interface {
	CertificateByID(id int64) (*tls.Certificate, error)
}

// ALPNProvider serves pending ACME TLS-ALPN-01 validation certificates from the
// existing listener, so the challenge never needs a second bind on port 443.
type ALPNProvider interface {
	Certificate(serverName string, protos []string) (*tls.Certificate, bool)
}

// Deps are the collaborators the proxy needs.
// PolicyEngine is the part of the policy engine the proxy needs. Two
// implementations satisfy it: a single engine (one site) and siteres.Router,
// which picks the engine of the site each request belongs to.
type PolicyEngine interface {
	DecoyHost(host string) bool
	Settings(siteID int64) policy.Settings
	Screen(req *policy.Request) model.Verdict
	Inspect(req *policy.Request) (model.Verdict, policy.WAFInfo)
	ResponseInspection(p *model.Proxy) (responses, mode string)
	// ResponseEngine compiles the profile the proxy names, for its own site.
	ResponseEngine(p *model.Proxy) *waf.Engine
	ProfileFor(p *model.Proxy) *model.Profile
}

type Deps struct {
	Store    *store.Store
	Policy   PolicyEngine
	Gate     *gate.Gate
	Bots     *botguard.Guard
	Bans     *ban.Engine
	Geo      *geoip.Geo
	Metrics  *metrics.Collector
	Log      *slog.Logger
	ClientIP *clientip.Resolver
}

type edge struct {
	proxy      model.Proxy
	protection *model.ProtectionProfile
	// waf is the selected WAF profile, kept for the limits it carries: the
	// response ceiling. The policy engine reads the same row for the rest.
	waf    *model.Profile
	ups    []*upstream
	routes []model.Route
	rr     uint64
	rp     *httputil.ReverseProxy
	cache  *responseCache
	cancel context.CancelFunc
	queue  time.Duration
	// bodyTimeout is how long this site's client may take to send its body.
	bodyTimeout time.Duration
	health      healthSettings
	site        *capLimiter
	clients     *clientLimiter
	timeout     time.Duration
	reqOps      []model.HeaderOp
	respOps     []model.HeaderOp
}

type ctxKey int

const ctxUpstream ctxKey = 1

// Server terminates TLS and serves every configured hostname.
type Server struct {
	d          Deps
	mu         sync.RWMutex
	reloadMu   sync.Mutex
	edges      map[string]*edge
	baseDomain string
	certs      CertProvider
	alpn       ALPNProvider
	self       *tls.Certificate
	transport  *http.Transport
	cache      *responseCache
	draining   atomic.Bool
	// httpChallenge answers ACME HTTP-01 on the plain-HTTP listener.
	httpChallenge http.Handler

	events  chan model.Event
	dropped atomic.Int64

	hardBody int64

	// budget bounds the requests buffered at once, by count and by bytes.
	budget             *budget
	defaultQueue       time.Duration
	defaultBodyTimeout time.Duration

	listenMu  sync.Mutex
	listenErr map[string]string
}

// New creates the proxy server with a temporary self-signed certificate.
func New(d Deps) (*Server, error) {
	self, err := selfSigned()
	if err != nil {
		return nil, err
	}
	s := &Server{
		d:                  d,
		edges:              map[string]*edge{},
		self:               self,
		events:             make(chan model.Event, 8192),
		hardBody:           8 << 20,
		defaultQueue:       DefaultQueue,
		defaultBodyTimeout: DefaultBodyTimeout,
	}
	s.budget = newBudget(DefaultMaxInflight, DefaultMaxBufferedBytes)
	// One cache for the process: 128 MiB total, at most 32 MiB per hostname,
	// so one site cannot evict every other site's entries.
	s.cache = newResponseCache(CacheBytes, 32<<20)
	// No Proxy field: an HTTP_PROXY in the service environment must never
	// carry customer traffic through a third party.
	s.transport = &http.Transport{
		DialContext:       (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true,
		// Sized for a busier edge: an 8 vCPU host runs several hundred
		// concurrent requests across a handful of backends, and the defaults
		// close upstream connections between bursts.
		MaxIdleConns:          1024,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return s, nil
}

// SetCertProvider installs the ACME certificate resolver.
func (s *Server) SetCertProvider(p CertProvider) { s.certs = p }

// SetALPNProvider installs the ACME TLS-ALPN-01 challenge store.
func (s *Server) SetALPNProvider(p ALPNProvider) { s.alpn = p }

// SetHTTPChallengeHandler installs the ACME HTTP-01 token handler used by the
// plain-HTTP listener.
func (s *Server) SetHTTPChallengeHandler(h http.Handler) { s.httpChallenge = h }

// RunHTTP serves the ACME challenge path and redirects everything else to
// HTTPS. An empty address disables the listener.
func (s *Server) RunHTTP(ctx context.Context, addr string) error {
	if strings.TrimSpace(addr) == "" {
		return nil
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           http.HandlerFunc(s.servePlainHTTP),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	s.d.Log.Info("http listener", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) servePlainHTTP(w http.ResponseWriter, r *http.Request) {
	PlainHTTPHandler(s.httpChallenge).ServeHTTP(w, r)
}

// PlainHTTPHandler answers ACME HTTP-01 challenges and redirects every other
// request to HTTPS. It is exported so the canary and integration tests exercise
// the same handler the listener serves.
func PlainHTTPHandler(challenge http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if challenge != nil && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			challenge.ServeHTTP(w, r)
			return
		}
		host := normalizeHost(r.Host)
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
}

// SetBodyLimit overrides the maximum buffered request body.
func (s *Server) SetBodyLimit(n int64) {
	if n > 0 {
		s.hardBody = n
	}
}

// DefaultMaxInflight is the request-count budget when none is configured. The
// byte budget is the other half: a count alone lets 256 large uploads hold two
// gigabytes while the CPU is still idle.
const DefaultMaxInflight = 256

// DefaultMaxBufferedBytes bounds the request memory held at once.
const DefaultMaxBufferedBytes = 512 << 20

// DefaultQueue is how long a request waits for budget before it is shed: long
// enough to smooth a burst, short enough that a client sees a 503 rather than a
// stall.
const DefaultQueue = 250 * time.Millisecond

// CacheBytes is the response cache's share of process memory, checked against
// the configured ceiling at startup.
const CacheBytes = 128 << 20

// DefaultBodyTimeout bounds how long a client may take to send its body, so a
// trickling upload cannot hold a budget slot. Zero disables the deadline.
const DefaultBodyTimeout = 30 * time.Second

// SetMaxInflight bounds how many requests may be in flight or buffered at once.
// It is called once at startup, before the listeners serve.
func (s *Server) SetMaxInflight(n int) {
	s.budget.setCount(int64(n))
}

// SetBudget sets the byte ceiling and how long a request waits for room before
// it is shed. Called once at startup, before the listeners serve.
func (s *Server) SetBudget(maxBytes int64, queue time.Duration) {
	s.defaultQueue = queue
	s.budget.setLimits(maxBytes)
}

// SetBodyTimeout sets how long a client may take to send its body; zero
// disables the deadline. Called once at startup, before the listeners serve.
func (s *Server) SetBodyTimeout(d time.Duration) {
	s.defaultBodyTimeout = d
}

// Capacity reports the current request budget: in flight, allowed, and how many
// requests have been refused because the budget was full.
func (s *Server) Capacity() (inflight, max int, shed int64) {
	count, maxCount, _, _, refused := s.budget.snapshot()
	return int(count), int(maxCount), refused
}

// Reload rebuilds every host route from the database.
func (s *Server) Reload(ctx context.Context) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	// Edges outlive the caller: an API request context must not cancel health
	// checks after the response is written.
	ctx = context.WithoutCancel(ctx)
	list, err := s.d.Store.ListProxies()
	if err != nil {
		return err
	}
	base, _ := s.d.Store.GetSetting("base_domain")

	s.mu.Lock()
	old := s.edges
	next := map[string]*edge{}
	s.baseDomain = strings.ToLower(strings.TrimSpace(base))
	s.mu.Unlock()

	for _, p := range list {
		e, err := s.buildEdge(ctx, p)
		if err != nil {
			s.d.Log.Error("build proxy route", "host", p.Hostname, "err", err)
			continue
		}
		if prev, ok := old[p.Hostname]; ok && prev.cancel != nil {
			prev.cancel()
		}
		next[p.Hostname] = e
	}

	s.mu.Lock()
	s.edges = next
	s.mu.Unlock()

	// Warm upstream connections are kept: rebuilding a route must not cost
	// every other site its pooled connections.
	for host, prev := range old {
		if _, keep := next[host]; !keep && prev.cancel != nil {
			prev.cancel()
		}
	}
	s.d.Log.Info("routes reloaded", "proxies", len(next))
	return nil
}

func (s *Server) buildEdge(ctx context.Context, p model.Proxy) (*edge, error) {
	ups := []*upstream{}
	list, err := s.d.Store.ListUpstreams(p.ID)
	if err != nil {
		return nil, err
	}
	for _, u := range list {
		if !u.Enabled {
			continue
		}
		up, err := newUpstream(u.URL, u.Weight, u.MaxConns)
		if err != nil {
			s.d.Log.Warn("invalid upstream", "proxy", p.Hostname, "url", u.URL, "err", err)
			continue
		}
		ups = append(ups, up)
	}
	routes, err := s.d.Store.ListRoutes(p.ID)
	if err != nil {
		return nil, err
	}
	child, cancel := context.WithCancel(ctx)
	e := &edge{proxy: p, ups: ups, routes: routes, cache: s.cache, cancel: cancel,
		queue: s.queueFor(p.SiteID), bodyTimeout: s.bodyTimeoutFor(p.SiteID),
		waf: s.d.Policy.ProfileFor(&p), health: healthFor(p),
		site: newCapLimiter(p.MaxInflight), clients: newClientLimiter(p.MaxInflightPerClient),
		timeout: time.Duration(p.UpstreamTimeout) * time.Second,
		reqOps:  p.RequestHeaders, respOps: p.ResponseHeaders}
	if p.ProtectionProfileID != nil {
		prof, err := s.d.Store.GetProtectionProfile(*p.ProtectionProfileID)
		if err != nil {
			s.d.Log.Warn("load protection profile", "proxy", p.Hostname, "err", err)
		} else {
			e.protection = prof
		}
	}

	e.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			up, _ := pr.In.Context().Value(ctxUpstream).(*upstream)
			if up == nil {
				return
			}
			pr.SetURL(up.url)
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
		},
		Transport:     &retryTransport{base: s.transport, retries: p.Retries},
		FlushInterval: 100 * time.Millisecond,
		ModifyResponse: func(res *http.Response) error {
			applyHeaderOps(e.respOps, res.Header)
			// A real 5xx is evidence the backend is unwell even when its probe
			// still answers.
			if res.StatusCode >= 500 {
				if up, ok := res.Request.Context().Value(ctxUpstream).(*upstream); ok {
					up.noteFailure(e.health)
				}
			}
			return s.modifyResponse(e, res)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if up, ok := r.Context().Value(ctxUpstream).(*upstream); ok {
				up.noteFailure(e.health)
			}
			// Once the response has started there is no status left to change:
			// writing an error page would append it to the truncated body.
			if hs, ok := w.(interface{ headersSent() bool }); ok && hs.headersSent() {
				s.d.Log.Warn("upstream failed after the response started", "host", p.Hostname, "err", err)
				return
			}
			s.d.Log.Warn("upstream error", "host", p.Hostname, "err", err)
			uniformError(w, upstreamErrorStatus(err))
		},
	}
	if len(ups) > 0 {
		go healthLoop(child, ups, e.health)
	}
	return e, nil
}

// queueFor is the site's queue wait: the process default unless the site sets
// queue_ms, where 0 means refuse at once.
func (s *Server) queueFor(siteID int64) time.Duration {
	kv, err := s.d.Store.SettingsFor(siteID)
	if err != nil {
		return s.defaultQueue
	}
	raw, ok := kv["queue_ms"]
	if !ok {
		return s.defaultQueue
	}
	ms, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || ms < 0 || ms > 5000 {
		return s.defaultQueue
	}
	return time.Duration(ms) * time.Millisecond
}

// bodyTimeoutFor is the site's body deadline: the process default unless the
// site sets body_timeout_s, where 0 disables it.
func (s *Server) bodyTimeoutFor(siteID int64) time.Duration {
	kv, err := s.d.Store.SettingsFor(siteID)
	if err != nil {
		return s.defaultBodyTimeout
	}
	raw, ok := kv["body_timeout_s"]
	if !ok {
		return s.defaultBodyTimeout
	}
	sec, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || sec < 0 || sec > 3600 {
		return s.defaultBodyTimeout
	}
	return time.Duration(sec) * time.Second
}

func (s *Server) lookup(host string) *edge {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.edges[host]
}

func (s *Server) allowedHost(host string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.edges[host]
	return ok
}

// Run listens on the first address and serves TLS until the context is
// cancelled. Extra addresses are optional tailnet listeners: a failure to bind
// one is recorded for the Tailscale page but must not take the WAN listener
// down.
func (s *Server) Run(ctx context.Context, addrs ...string) error {
	lns, err := s.Listen(ctx, addrs...)
	if err != nil {
		return err
	}
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-stopped:
		}
		lns.DrainTimeout(10 * time.Second)
	}()
	err = lns.Serve()
	close(stopped)
	lns.DrainTimeout(10 * time.Second)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Listeners is a bound set of proxy listeners. Bind and serve are separate so
// a node taking over the service address can hold the port before it is allowed
// to answer, and release it without exiting the process.
type Listeners struct {
	s       *Server
	ctx     context.Context
	lns     []net.Listener
	servers []*http.Server
	bound   []string
	events  sync.Once
}

// Listen binds the addresses but serves nothing yet. The first address is
// required; extra addresses are optional and a failure to bind one is recorded
// for the Tailscale page instead of taking the primary listener down.
func (s *Server) Listen(ctx context.Context, addrs ...string) (*Listeners, error) {
	return s.ListenWith(ctx, func(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }, addrs...)
}

// ListenWith is Listen with a caller-chosen binder. A standby uses it with
// netbind.Listen to hold the service address with IP_FREEBIND before the
// address is moved to it, so a promotion serves without waiting for a bind.
func (s *Server) ListenWith(ctx context.Context, bind func(addr string) (net.Listener, error), addrs ...string) (*Listeners, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no proxy listen address")
	}
	if bind == nil {
		bind = func(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }
	}
	seen := map[string]bool{}
	out := &Listeners{s: s, ctx: ctx}
	for i, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" || seen[addr] {
			continue
		}
		ln, err := bind(addr)
		if err != nil {
			if i == 0 {
				out.Close()
				return nil, fmt.Errorf("listen %s: %w", addr, err)
			}
			s.setListenError(addr, err)
			s.d.Log.Error("extra proxy listener failed", "addr", addr, "err", err)
			continue
		}
		seen[addr] = true
		out.lns = append(out.lns, ln)
		out.bound = append(out.bound, addr)
		s.clearListenError(addr)
	}
	if len(out.lns) == 0 {
		return nil, fmt.Errorf("no proxy listeners bound")
	}
	for range out.lns {
		out.servers = append(out.servers, &http.Server{
			Handler:           s,
			ReadHeaderTimeout: 10 * time.Second,
			// Headers and the handshake are bounded here; a request body is
			// bounded by the site's own deadline in the handler, and writes stay
			// unbounded so SSE and large streamed downloads are not cut off.
			IdleTimeout:    90 * time.Second,
			MaxHeaderBytes: 32 << 10,
			ErrorLog:       nil,
		})
	}
	return out, nil
}

// Addrs reports the addresses that were bound.
func (l *Listeners) Addrs() []string { return append([]string(nil), l.bound...) }

// Serve starts the bound listeners and blocks until the first one stops or
// fails. It does not own the shutdown decision; Drain and Close do.
func (l *Listeners) Serve() error {
	if len(l.lns) == 0 {
		return fmt.Errorf("no proxy listeners bound")
	}
	l.events.Do(func() { go l.s.eventWriter(l.ctx) })
	errCh := make(chan error, len(l.servers))
	for i, srv := range l.servers {
		tlsLn := tls.NewListener(l.s.d.Metrics.CountingListener(l.lns[i]), l.s.tlsConfig())
		addr := l.bound[i]
		go func() {
			l.s.d.Log.Info("proxy listening", "addr", addr)
			errCh <- srv.Serve(tlsLn)
		}()
	}
	return <-errCh
}

// Drain stops accepting, lets in-flight requests finish within ctx and closes
// the sockets. A node that is standing down calls this before it gives up the
// service address.
func (l *Listeners) Drain(ctx context.Context) {
	l.s.draining.Store(true)
	for _, srv := range l.servers {
		_ = srv.Shutdown(ctx)
	}
	for _, ln := range l.lns {
		_ = ln.Close()
	}
}

// DrainTimeout is Drain with a bounded budget.
func (l *Listeners) DrainTimeout(d time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	l.Drain(ctx)
}

// Close releases the sockets immediately. It is safe on a partially bound set
// and on a listener that never served.
func (l *Listeners) Close() {
	for _, srv := range l.servers {
		_ = srv.Close()
	}
	for _, ln := range l.lns {
		_ = ln.Close()
	}
}

// SetDraining marks the server ready or draining. Promotion clears a previous
// drain so the new active reports ready without a restart.
func (s *Server) SetDraining(v bool) { s.draining.Store(v) }

func (s *Server) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS12,
		NextProtos:             []string{"h2", "http/1.1", "acme-tls/1"},
		GetCertificate:         s.getCertificate,
		GetConfigForClient:     s.siteTLSConfig,
		SessionTicketsDisabled: false,
		CurvePreferences:       []tls.CurveID{tls.X25519, tls.CurveP256},
	}
}

// tlsVersionFor maps a site's setting to a tls constant. Empty means 1.2.
func tlsVersionFor(v string) uint16 {
	if v == "1.3" {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

// siteTLSConfig raises the minimum version for a site that asks for TLS 1.3,
// without changing the default for every other host.
func (s *Server) siteTLSConfig(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	e := s.lookup(normalizeHost(hello.ServerName))
	if e == nil || e.proxy.TLSMinVersion != "1.3" {
		return nil, nil
	}
	c := s.tlsConfig()
	c.GetConfigForClient = nil
	c.MinVersion = tlsVersionFor(e.proxy.TLSMinVersion)
	return c, nil
}

func (s *Server) setListenError(addr string, err error) {
	s.listenMu.Lock()
	defer s.listenMu.Unlock()
	if s.listenErr == nil {
		s.listenErr = map[string]string{}
	}
	s.listenErr[addr] = err.Error()
}

func (s *Server) clearListenError(addr string) {
	s.listenMu.Lock()
	defer s.listenMu.Unlock()
	delete(s.listenErr, addr)
}

// ListenerError reports why an optional proxy listener did not bind, or an
// empty string when it is healthy.
func (s *Server) ListenerError(addr string) string {
	s.listenMu.Lock()
	defer s.listenMu.Unlock()
	return s.listenErr[addr]
}

func (s *Server) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := normalizeHost(hello.ServerName)
	// An ACME TLS-ALPN-01 validation names a hostname that may not be routed
	// yet, so the challenge store is consulted before the route allowlist.
	if s.alpn != nil {
		if cert, ok := s.alpn.Certificate(host, hello.SupportedProtos); ok {
			return cert, nil
		}
	}
	if !s.allowedHost(host) {
		return nil, fmt.Errorf("unknown server name %q", host)
	}
	// A site that names a certificate gets exactly that certificate; SNI
	// matching is only the fallback.
	if e := s.lookup(host); e != nil && e.proxy.CertID != nil {
		if p, ok := s.certs.(CertByIDProvider); ok {
			if cert, err := p.CertificateByID(*e.proxy.CertID); err == nil && cert != nil {
				return cert, nil
			}
		}
	}
	if s.certs != nil {
		if cert, err := s.certs.GetCertificate(hello); err == nil && cert != nil {
			return cert, nil
		} else if err != nil {
			s.d.Log.Debug("certificate resolver miss", "host", host, "err", err)
		}
	}
	return s.self, nil
}

func (s *Server) eventWriter(ctx context.Context) {
	var access *os.File
	if path := os.Getenv("WAFPROXY_ACCESS_LOG"); path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			s.d.Log.Warn("access log unavailable", "path", path, "err", err)
		} else {
			access = f
			defer access.Close()
		}
	}
	accessJSON := strings.EqualFold(os.Getenv("WAFPROXY_ACCESS_LOG_FORMAT"), "json")
	batch := make([]model.Event, 0, 256)
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		out := append([]model.Event(nil), batch...)
		batch = batch[:0]
		if access != nil {
			for _, e := range out {
				if accessJSON {
					if line, err := json.Marshal(e); err == nil {
						_, _ = access.Write(append(line, '\n'))
					}
					continue
				}
				// nginx combined format so the stock CrowdSec nginx parser can read it.
				fmt.Fprintf(access, "%s - - [%s] %s %d %d %q %q\n",
					e.SrcIP, e.TS.Format("02/Jan/2006:15:04:05 -0700"),
					strconv.Quote(e.Method+" "+e.Path+" HTTP/1.1"), e.Status, e.BytesOut, "-", e.UA)
			}
		}
		if err := s.d.Store.InsertEvents(out); err != nil {
			s.d.Log.Error("insert events", "err", err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case e := <-s.events:
			batch = append(batch, e)
			if len(batch) >= 256 {
				flush()
			}
		case <-timer.C:
			flush()
			timer.Reset(250 * time.Millisecond)
		}
	}
}

// record queues an audit event, dropping it when the writer is saturated.
func (s *Server) record(e model.Event) {
	select {
	case s.events <- e:
	default:
		s.dropped.Add(1)
	}
}

// Dropped returns how many events were dropped under backpressure.
func (s *Server) Dropped() int64 { return s.dropped.Load() }

// Ready reports whether the listener is accepting new work. It turns false as
// soon as shutdown starts, before the port closes.
func (s *Server) Ready() bool { return !s.draining.Load() }

// PurgeCache drops cached responses for one host, or all of them when host is
// empty, and returns how many entries were removed.
func (s *Server) PurgeCache(host string) int {
	if s.cache == nil {
		return 0
	}
	return s.cache.purge(strings.ToLower(strings.TrimSpace(host)))
}

func selfSigned() (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "wafproxy.local"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"wafproxy.local", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h, "]") {
		h = h[:i]
	}
	return strings.TrimSuffix(h, ".")
}
