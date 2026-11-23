package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ha"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/netbind"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/proxy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/streaming"
)

// dataPlane is what a node may only do while active: terminate TLS, forward
// streaming traffic and answer ACME HTTP-01. A standby holds the service
// address without accepting, so a promotion serves without waiting for a bind
// and a demotion gives the address up without exiting the process.
type dataPlane struct {
	px      *proxy.Server
	streams *streaming.Manager
	cfgs    map[string]streaming.Config
	wan     string
	http    string
	tail    string
	log     *slog.Logger

	mu      sync.Mutex
	prebind *proxy.Listeners
	active  *proxy.Listeners
	cancel  context.CancelFunc
	serving bool
}

func newDataPlane(px *proxy.Server, streams *streaming.Manager, cfgs map[string]streaming.Config,
	wan, httpAddr, tail string, log *slog.Logger) *dataPlane {
	return &dataPlane{px: px, streams: streams, cfgs: cfgs, wan: wan, http: httpAddr, tail: tail, log: log}
}

// freebind holds an address that is not local yet. IP_FREEBIND is Linux-only;
// elsewhere the ordinary bind fails until the address moves, and Serve binds
// again at promotion.
func freebind(addr string) (net.Listener, error) {
	ln, err := netbind.Listen("tcp", addr)
	if err != nil && errors.Is(err, netbind.ErrUnsupported) {
		return net.Listen("tcp", addr)
	}
	return ln, err
}

// Prebind binds the service address without serving. It is best-effort: the
// promotion path binds again if this did not stick.
func (p *dataPlane) Prebind(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.prebind != nil || p.serving {
		return nil
	}
	lns, err := p.px.ListenWith(ctx, freebind, p.wan, p.tail)
	if err != nil {
		return err
	}
	p.prebind = lns
	return nil
}

// Addrs lists the addresses currently held, for the boot log.
func (p *dataPlane) Addrs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case p.active != nil:
		return p.active.Addrs()
	case p.prebind != nil:
		return p.prebind.Addrs()
	}
	return nil
}

// Serve starts the listener, the forwarders and the ACME HTTP listener. It
// returns once they are running; a later failure is logged, not returned, so a
// promotion is not reported as failed after traffic already moved.
func (p *dataPlane) Serve(ctx context.Context) error {
	p.mu.Lock()
	if p.serving {
		p.mu.Unlock()
		return nil
	}
	lns := p.prebind
	p.prebind = nil
	serveCtx, cancel := context.WithCancel(ctx)
	p.mu.Unlock()

	p.px.SetDraining(false)
	// Forwarders rebind from the replicated settings. One that cannot bind is
	// reported but must not stop the HTTP listener: it is a separate service.
	if err := p.streams.ApplyAll(p.cfgs); err != nil {
		p.log.Warn("streaming forwarder not started", "err", err)
	}
	if strings.TrimSpace(p.http) != "" {
		go func() {
			if err := p.px.RunHTTP(serveCtx, p.http); err != nil {
				p.log.Warn("http listener failed", "addr", p.http, "err", err)
			}
		}()
	}
	if lns == nil {
		var err error
		lns, err = p.px.Listen(serveCtx, p.wan, p.tail)
		if err != nil {
			cancel()
			p.streams.Close()
			return err
		}
	}
	go func() {
		if err := lns.Serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			p.log.Error("proxy listener stopped", "err", err)
		}
	}()

	p.mu.Lock()
	p.active = lns
	p.cancel = cancel
	p.serving = true
	p.mu.Unlock()
	p.log.Info("data plane serving", "addrs", lns.Addrs())
	return nil
}

// Drain stops accepting, finishes in-flight requests within a bounded budget,
// and closes the forwarders. The node keeps its console and control socket.
func (p *dataPlane) Drain(ctx context.Context) {
	p.mu.Lock()
	lns, cancel := p.active, p.cancel
	was := p.serving
	p.active, p.cancel, p.serving = nil, nil, false
	p.mu.Unlock()
	if !was && lns == nil {
		return
	}
	if cancel != nil {
		cancel()
	}
	if lns != nil {
		// Give handlers the promotion's budget, capped so a demotion cannot
		// hang on one slow upload.
		budget := 10 * time.Second
		if d, ok := ctx.Deadline(); ok {
			budget = min(budget, time.Until(d))
		}
		lns.DrainTimeout(max(budget, time.Second))
	}
	p.streams.Close()
	p.log.Info("data plane drained")
}

// Close releases everything held for shutdown.
func (p *dataPlane) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p.Drain(ctx)
	p.mu.Lock()
	pre := p.prebind
	p.prebind = nil
	p.mu.Unlock()
	if pre != nil {
		pre.Close()
	}
}

// activeSupervisor runs the loops a node may only run while active. It is
// restartable: a demoted node stops them, and a second promotion starts them
// again with a fresh context instead of leaving the process half alive.
type activeSupervisor struct {
	root context.Context

	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	fns     []func(context.Context)
	running bool
}

func newActiveSupervisor(root context.Context) *activeSupervisor {
	return &activeSupervisor{root: root}
}

// Add registers work to start with the active role. Call it before Start.
func (a *activeSupervisor) Add(fn func(context.Context)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fns = append(a.fns, fn)
}

// Start is idempotent.
func (a *activeSupervisor) Start() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.running {
		return
	}
	a.ctx, a.cancel = context.WithCancel(a.root)
	a.running = true
	for _, fn := range a.fns {
		go fn(a.ctx)
	}
}

// Stop cancels the running loops. A later Start launches them again.
func (a *activeSupervisor) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.running {
		return
	}
	a.cancel()
	a.ctx, a.cancel = nil, nil
	a.running = false
}

// replicator runs the standby's stream follower. It is restartable: a node that
// is demoted starts it again, and a node that is promoted stops it before it
// serves, or it would overwrite its own writes from the old active.
type replicator struct {
	root    context.Context
	dataDir string
	st      *store.Store
	log     *slog.Logger

	mu     sync.Mutex
	cancel context.CancelFunc
}

func newReplicator(root context.Context, dataDir string, st *store.Store, log *slog.Logger) *replicator {
	return &replicator{root: root, dataDir: dataDir, st: st, log: log}
}

// Start is idempotent and does nothing on an unpaired node.
func (r *replicator) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		return
	}
	if pair, err := ha.LoadPair(r.dataDir); err != nil || pair == nil {
		return
	}
	ctx, cancel := context.WithCancel(r.root)
	r.cancel = cancel
	r.log.Info("ha replication started")
	go func() {
		ha.OutboxLoop(ctx, r.dataDir, r.st, time.Second, 30, func(err error) {
			r.log.Warn("ha replication failed", "err", err)
		})
	}()
}

// Stop is safe to call when nothing is running.
func (r *replicator) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel == nil {
		return
	}
	r.cancel()
	r.cancel = nil
}
