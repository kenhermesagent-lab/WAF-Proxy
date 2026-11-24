package mcp

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/streaming"
)

// Router hands each request to the gateway of the site its token belongs to.
// Tokens are minted per site, so a token issued for one tenant reads and writes
// only that tenant's rows even though every token reaches the same /mcp path.
type Router struct {
	st        *store.Store
	bans      *ban.Engine
	log       *slog.Logger
	opts      Options
	limiter   *auth.Limiter
	streams   *streaming.Manager
	defaultID int64

	mu     sync.Mutex
	bySite map[int64]*Gateway
}

// NewRouter resolves tokens across sites, so st must be an unscoped handle: a
// bearer token has to be found whichever site minted it.
func NewRouter(st *store.Store, bans *ban.Engine, log *slog.Logger, opts Options) *Router {
	r := &Router{
		st: st, bans: bans, log: log, opts: opts,
		limiter: auth.NewLimiter(), bySite: map[int64]*Gateway{},
	}
	if def, err := st.SiteBySlug(store.DefaultSiteSlug); err == nil && def != nil {
		r.defaultID = def.ID
	}
	return r
}

// SetStreaming attaches the media relay to each site's gateway, including the
// ones built after this call.
func (r *Router) SetStreaming(m *streaming.Manager) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.streams = m
	for _, g := range r.bySite {
		g.SetStreaming(m)
	}
}

// Start prunes the rate-limit buckets the gateways share.
func (r *Router) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r.limiter.Cleanup()
			}
		}
	}()
}

func (r *Router) ServeHTTP(w http.ResponseWriter, rq *http.Request) {
	g := r.gateway(r.tokenSite(rq))
	if g == nil {
		writeHTTPError(w, http.StatusServiceUnavailable, "the MCP gateway has no site to serve")
		return
	}
	g.ServeHTTP(w, rq)
}

// tokenSite is the site that minted the bearer token. An environment token, an
// unknown token and a token stored before sites existed all fall back to the
// default site, whose gateway then decides whether the credential is valid.
func (r *Router) tokenSite(rq *http.Request) int64 {
	raw := bearerToken(rq.Header.Get("Authorization"))
	if raw == "" {
		return r.defaultID
	}
	t, err := r.st.MCPTokenByHash(HashToken(raw))
	if err != nil || t.SiteID == 0 {
		return r.defaultID
	}
	return t.SiteID
}

func (r *Router) gateway(id int64) *Gateway {
	if id == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if g, ok := r.bySite[id]; ok {
		return g
	}
	g := New(r.st.InSite(id), r.bans, r.log, r.opts)
	g.limiter = r.limiter
	g.SetStreaming(r.streams)
	r.bySite[id] = g
	return g
}
