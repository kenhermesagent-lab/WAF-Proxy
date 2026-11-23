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
	waf     *model.Profile
	ups     []*upstream
	routes  []model.Route
	rr      uint64
	rp      *httputil.ReverseProxy
	cache   *responseCache
	cancel  context.CancelFunc
	health  healthSettings
	site    *capLimiter
	clients *clientLimiter
	timeout time.Duration
	reqOps  []model.HeaderOp
	respOps []model.HeaderOp
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

	// inflight bounds the requests buffered at once; shed counts the ones
	// refused because that budget was full.
	inflight    chan struct{}
	inflightN   atomic.Int64
	maxInflight atomic.Int64
	shed        atomic.Int64

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
		d:        d,
		edges:    map[string]*edge{},
		self:     self,
		events:   make(chan model.Event, 8192),
		hardBody: 8 << 20,
	}
	s.SetMaxInflight(DefaultMaxInflight)
	// One cache for the process: 128 MiB total, at most 32 MiB per hostname,
	// so one site cannot evict every other site's entries.
	s.cache = newResponseCache(128<<20, 32<<20)
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

// DefaultMaxInflight is the request budget when none is configured. With the
// 8 MiB body ceiling this keeps the worst case near a gigabyte rather than
// letting a few hundred concurrent uploads take the host down.
const DefaultMaxInflight = 128

// SetMaxInflight bounds how many requests may be in flight or buffered at once.
// It is called once at startup, before the listeners serve.
func (s *Server) SetMaxInflight(n int) {
	if n <= 0 {
		n = DefaultMaxInflight
	}
	s.maxInflight.Store(int64(n))
	s.inflight = make(chan struct{}, n)
}

// Capacity reports the current request budget: in flight, allowed, and how many
// requests have been refused because the budget was full.
func (s *Server) Capacity() (inflight, max int, shed int64) {
	return int(s.inflightN.Load()), int(s.maxInflight.Load()), s.shed.Load()
}

func (s *Server) acquire() bool {
	if s.inflight == nil {
		return true
	}
	select {
	case s.inflight <- struct{}{}:
		s.inflightN.Add(1)
		return true
	default:
		s.shed.Add(1)
		return false
	}
}

func (s *Server) release() {
	if s.inflight == nil {
		return
	}
	<-s.inflight
	s.inflightN.Add(-1)
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
	if len(addrs) == 0 {
		return fmt.Errorf("no proxy listen address")
	}
	seen := map[string]bool{}
	var lns []net.Listener
	var bound []string
	for i, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" || seen[addr] {
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			if i == 0 {
				for _, l := range lns {
					_ = l.Close()
				}
				return fmt.Errorf("listen %s: %w", addr, err)
			}
			s.setListenError(addr, err)
			s.d.Log.Error("extra proxy listener failed", "addr", addr, "err", err)
			continue
		}
		seen[addr] = true
		lns = append(lns, ln)
		bound = append(bound, addr)
		s.clearListenError(addr)
	}
	if len(lns) == 0 {
		return fmt.Errorf("no proxy listeners bound")
	}

	servers := make([]*http.Server, 0, len(lns))
	for range lns {
		servers = append(servers, &http.Server{
			Handler:           s,
			ReadHeaderTimeout: 10 * time.Second,
			// Bound slow request bodies (slowloris) while leaving writes unbounded
			// so SSE and large streamed downloads are not cut off.
			ReadTimeout:    60 * time.Second,
			IdleTimeout:    90 * time.Second,
			MaxHeaderBytes: 32 << 10,
			ErrorLog:       nil,
		})
	}
	go s.eventWriter(ctx)
	errCh := make(chan error, len(servers))
	for i, srv := range servers {
		tlsLn := tls.NewListener(s.d.Metrics.CountingListener(lns[i]), s.tlsConfig())
		addr := bound[i]
		go func() {
			s.d.Log.Info("proxy listening", "addr", addr)
			errCh <- srv.Serve(tlsLn)
		}()
	}

	shutdown := func() {
		s.draining.Store(true)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, srv := range servers {
			_ = srv.Shutdown(shutdownCtx)
		}
		for _, ln := range lns {
			_ = ln.Close()
		}
	}
	go func() {
		<-ctx.Done()
		shutdown()
	}()

	err := <-errCh
	shutdown()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

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
