// Package siteres builds one instance of every configuration-driven resource
// per site, so a site's policies, notification channels, anomaly thresholds,
// canary target and ACME account belong to that site alone. Each instance reads
// and writes through a store handle scoped to its site, which is what keeps one
// tenant's settings out of another's.
//
// A single-site install is the site called default. Everything an earlier
// release wrote lives there, so an upgrade keeps serving exactly the
// configuration it had: the default instance reads the same rows and settings
// it always did, and a new site starts from the shipped defaults.
package siteres

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/acme"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/anomaly"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/canary"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/intel"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/notify"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/policy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/scantrust"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

// Deps are the process-wide pieces every site's instances share.
type Deps struct {
	Store   *store.Store
	Box     *wfcrypto.Box
	Log     *slog.Logger
	Bans    *ban.Engine
	Feeds   *intel.Manager
	Geo     *geoip.Geo
	Metrics *metrics.Collector
	// Bundles returns the rule packs every site compiles, or nil.
	Bundles func() []waf.Bundle
	// Prober runs the canary check; nil uses the real network prober.
	Prober canary.Probe
	// ScanTrust holds the tokens of running scans, so their probes are exempt
	// from bans, decoys and rate limiting.
	ScanTrust *scantrust.Registry
	// ACMEDirectory and ACMECAFile are host-wide: one CA, one staging switch.
	ACMEDirectory string
	ACMECAFile    string
}

// Bundle is one site's set of instances.
type Bundle struct {
	Site model.Site
	// Store is this site's handle; every instance above reads through it.
	Store   *store.Store
	Policy  *policy.Engine
	Notify  *notify.Manager
	Anomaly *anomaly.Manager
	Canary  *canary.Monitor
	ACME    *acme.Manager
	Wafs    *waf.Set
	// Bans and ScanTrust are process-wide; the loop and the API read them
	// through the bundle they already have.
	Bans      *ban.Engine
	ScanTrust *scantrust.Registry

	// started guards the background loops that must run once per instance.
	started bool
}

// Set owns one bundle per site and creates it on first use.
type Set struct {
	deps  Deps
	mu    sync.Mutex
	sites map[int64]*Bundle
}

// New builds the default site's instances eagerly, so a failure there is
// reported at startup instead of on the first request.
func New(d Deps) (*Set, error) {
	s := &Set{deps: d, sites: map[int64]*Bundle{}}
	if _, err := s.For(d.Store.SiteID()); err != nil {
		return nil, err
	}
	return s, nil
}

// DefaultID is the site every pre-sites row was adopted by.
func (s *Set) DefaultID() int64 { return s.deps.Store.SiteID() }

// Default returns the default site's bundle, which always exists after New.
func (s *Set) Default() *Bundle {
	b, err := s.For(s.DefaultID())
	if err != nil {
		return nil
	}
	return b
}

// For returns the bundle for a site, building it on first use. A site id that
// no longer exists (a delete racing a request) falls back to the default
// bundle, which reads no tenant rows beyond its own.
func (s *Set) For(id int64) (*Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.sites[id]; ok {
		return b, nil
	}
	site, err := s.deps.Store.SiteByID(id)
	if err != nil {
		if id == s.DefaultID() {
			return nil, err
		}
		return s.sites[s.DefaultID()], nil
	}
	b, err := s.build(*site)
	if err != nil {
		return nil, err
	}
	s.sites[id] = b
	return b, nil
}

// build creates the five instances with a store handle scoped to the site.
func (s *Set) build(site model.Site) (*Bundle, error) {
	d := s.deps
	scoped := d.Store.InSite(site.ID)
	profiles, err := scoped.ListProfiles()
	if err != nil {
		return nil, err
	}
	wafs := waf.NewSet(profiles, d.Log)
	if d.Bundles != nil {
		wafs.SetBundles(d.Bundles())
	}
	certs := acme.New(scoped, d.Box, d.Log)
	certs.SetDirectory(d.ACMEDirectory, d.ACMECAFile)
	nt := notify.New(scoped, d.Box, d.Log)
	pol, err := policy.New(scoped, d.Bans, d.Feeds, d.Geo, wafs, d.Log)
	if err != nil {
		return nil, err
	}
	if d.Bundles != nil {
		pol.SetBundleRules(d.Bundles)
	}
	if d.ScanTrust != nil {
		pol.ScanTrust = d.ScanTrust.Valid
	}
	prober := d.Prober
	if prober == nil {
		prober = canary.Prober{}
	}
	return &Bundle{
		Site:      site,
		Store:     scoped,
		Policy:    pol,
		Notify:    nt,
		Anomaly:   anomaly.New(scoped, d.Metrics, nt, d.Log),
		Canary:    canary.NewMonitor(scoped, prober, nt),
		ACME:      certs,
		Wafs:      wafs,
		Bans:      d.Bans,
		ScanTrust: d.ScanTrust,
	}, nil
}

// Reload rebuilds one site's compiled policy after a configuration write. A
// write on one site never recompiles another's.
func (s *Set) Reload(siteID int64) error {
	b, err := s.For(siteID)
	if err != nil {
		return err
	}
	return b.Policy.Reload()
}

// Each calls fn for every bundle that exists, under the set's lock so a site
// cannot be half-built while a loop walks the list.
func (s *Set) Each(fn func(*Bundle)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.sites {
		fn(b)
	}
}

// Start runs each instance's background loops. Sites created later start on the
// next poll, so the console's "create site" needs no restart.
func (s *Set) Start(ctx context.Context) {
	s.startAll(ctx)
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.startAll(ctx)
		}
	}
}

// startAll builds the bundles of sites created since the last poll and starts
// the loops of any bundle that has not started them.
func (s *Set) startAll(ctx context.Context) {
	sites, err := s.deps.Store.ListSites()
	if err != nil {
		s.deps.Log.Error("list sites for per-site engines", "err", err)
		return
	}
	for _, site := range sites {
		b, err := s.For(site.ID)
		if err != nil {
			s.deps.Log.Error("build per-site engines", "site", site.Slug, "err", err)
			continue
		}
		s.mu.Lock()
		first := !b.started
		b.started = true
		s.mu.Unlock()
		if first {
			go b.Policy.Start(ctx)
			go b.Notify.Start(ctx)
			go b.Anomaly.Start(ctx)
			go b.Canary.Start(ctx)
			go b.ACME.RenewLoop(ctx)
		}
	}
}

// Reset clears the started flags so a node that was demoted and promoted again
// relaunches every site's loops. Start only launches loops for a bundle it has
// not started yet, so without this a second promotion would run no renewals.
func (s *Set) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.sites {
		b.started = false
	}
}

// Drop forgets a site's instances. Their loops stop with the process's context
// when the site's rows are gone; nothing here holds a handle to deleted data.
func (s *Set) Drop(siteID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sites, siteID)
}

// CertificateForHost finds the site that holds a certificate for a name.
func (s *Set) CertificateForHost(host string) (*tls.Certificate, error) {
	var found *tls.Certificate
	var failure error
	s.Each(func(b *Bundle) {
		if found != nil {
			return
		}
		c, err := b.ACME.CertificateForHost(host)
		if err == nil {
			found = c
			return
		}
		if failure == nil {
			failure = err
		}
	})
	if found != nil {
		return found, nil
	}
	if failure == nil {
		failure = fmt.Errorf("no certificate for %q", host)
	}
	return nil, failure
}

// GetCertificate answers one handshake from whichever site holds the name. One
// listener serves every site's hostnames, so a certificate issued in one site's
// console is served without another site being able to see it.
func (s *Set) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.CertificateForHost(hello.ServerName)
}

// CertificateByID resolves the certificate a proxy pinned, from any site: the
// id is unique across the install.
func (s *Set) CertificateByID(id int64) (*tls.Certificate, error) {
	var found *tls.Certificate
	var failure error
	s.Each(func(b *Bundle) {
		if found != nil {
			return
		}
		c, err := b.ACME.CertificateByID(id)
		if err == nil {
			found = c
			return
		}
		if failure == nil {
			failure = err
		}
	})
	if found != nil {
		return found, nil
	}
	if failure == nil {
		failure = fmt.Errorf("certificate %d not found", id)
	}
	return nil, failure
}

// Certificate answers a TLS-ALPN-01 handshake: the challenge lives in the
// issuing site's ACME client.
func (s *Set) Certificate(serverName string, protos []string) (*tls.Certificate, bool) {
	var cert *tls.Certificate
	s.Each(func(b *Bundle) {
		if cert != nil {
			return
		}
		if c, ok := b.ACME.TLSALPN().Certificate(serverName, protos); ok {
			cert = c
		}
	})
	return cert, cert != nil
}

// HTTPChallenge serves HTTP-01 tokens from every site's ACME client, because
// one plain-HTTP listener answers all of them.
func (s *Set) HTTPChallenge() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var captured *captureWriter
		s.Each(func(b *Bundle) {
			if captured != nil {
				return
			}
			rec := &captureWriter{header: http.Header{}, status: http.StatusNotFound}
			b.ACME.HTTP01().ServeHTTP(rec, r)
			if rec.status != http.StatusNotFound {
				captured = rec
			}
		})
		if captured == nil {
			http.NotFound(w, r)
			return
		}
		for k, v := range captured.header {
			w.Header()[k] = v
		}
		w.WriteHeader(captured.status)
		_, _ = w.Write(captured.body)
	})
}

// captureWriter collects a handler's answer so another site's handler can be
// asked whether it owns the request.
type captureWriter struct {
	header http.Header
	status int
	body   []byte
}

func (c *captureWriter) Header() http.Header    { return c.header }
func (c *captureWriter) WriteHeader(status int) { c.status = status }
func (c *captureWriter) Write(p []byte) (int, error) {
	c.body = append(c.body, p...)
	return len(p), nil
}

// Router is the policy engine the proxy asks, one instance per site. A request
// is decided by the instances of the site its hostname belongs to.
type Router struct{ set *Set }

// NewRouter wraps a set for the proxy's request path.
func NewRouter(set *Set) *Router { return &Router{set: set} }

func (r *Router) engine(siteID int64) *policy.Engine {
	if b, err := r.set.For(siteID); err == nil {
		return b.Policy
	}
	return nil
}

// DecoyHost reports whether any site treats a hostname as a decoy: the host is
// not served, so no single site owns the decision.
func (r *Router) DecoyHost(host string) bool {
	found := false
	r.set.Each(func(b *Bundle) {
		if !found && b.Policy.DecoyHost(host) {
			found = true
		}
	})
	return found
}

// Settings is the site's cached view of its settings rows.
func (r *Router) Settings(siteID int64) policy.Settings {
	if e := r.engine(siteID); e != nil {
		return e.CurrentSettings()
	}
	return policy.Settings{}
}

// Screen decides the header-only stages for the request's site.
func (r *Router) Screen(req *policy.Request) model.Verdict {
	if e := r.requestEngine(req); e != nil {
		return e.Screen(req)
	}
	return model.Verdict{Action: "allow"}
}

// InList matches the request's client against the named lists of its site.
func (r *Router) InList(req *policy.Request, ids []int64) bool {
	if e := r.requestEngine(req); e != nil {
		return e.InList(req, ids)
	}
	return false
}

// Inspect runs the body stages for the request's site.
func (r *Router) Inspect(req *policy.Request) (model.Verdict, policy.WAFInfo) {
	if e := r.requestEngine(req); e != nil {
		return e.Inspect(req)
	}
	return model.Verdict{Action: "allow"}, policy.WAFInfo{}
}

// ResponseInspection reads the proxy's profile from its own site.
func (r *Router) ResponseInspection(p *model.Proxy) (string, string) {
	if p == nil {
		return "", ""
	}
	if e := r.engine(p.SiteID); e != nil {
		return e.ResponseInspection(p)
	}
	return "", ""
}

// ResponseEngine compiles the profile the proxy names, from its own site.
func (r *Router) ResponseEngine(p *model.Proxy) *waf.Engine {
	if p == nil {
		return nil
	}
	if e := r.engine(p.SiteID); e != nil {
		return e.WAFEngine(p.ProfileID)
	}
	return nil
}

// ProfileFor reads the proxy's WAF profile row from its own site.
func (r *Router) ProfileFor(p *model.Proxy) *model.Profile {
	if p == nil {
		return nil
	}
	if e := r.engine(p.SiteID); e != nil {
		return e.ProfileFor(p)
	}
	return nil
}

func (r *Router) requestEngine(req *policy.Request) *policy.Engine {
	if req == nil || req.Proxy == nil {
		return r.engine(r.set.DefaultID())
	}
	return r.engine(req.Proxy.SiteID)
}
