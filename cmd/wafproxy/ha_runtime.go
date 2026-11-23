package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/api"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ha"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/siteres"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// haRuntime ties a move's hooks to the process: preflight reads the live store,
// and the irreversible steps start and stop the data plane and its loops.
type haRuntime struct {
	// root outlives every move. The lease keeper and the data plane belong to
	// the process, not to the promotion that started them: the manager cancels
	// the move's context as soon as it returns.
	root    context.Context
	dir     string
	st      *store.Store
	all     *store.Store
	res     *siteres.Set
	bans    *ban.Engine
	api     *api.Server
	plane   *dataPlane
	active  *activeSupervisor
	repl    *replicator
	ident   *ha.Identity
	quiesce *ha.Quiesce
	// mgr is the control-socket move coordinator; a lost witness lease
	// self-demotes through it, so it never races an operator's move.
	mgr *ha.Manager
	// witness is nil unless a lease authority is configured.
	witness     *ha.WitnessClient
	leaseCancel context.CancelFunc
	// auto is nil unless unattended promotion is enabled. The watcher runs on
	// both roles: an active node uses it for the epoch conflict check, a
	// standby for the promotion gate.
	auto         *ha.AutoPromoter
	autoFailover bool
	monitor      *ha.Monitor
	peer         *peerWatch
	flap         *ha.FlapGuard
	fence        string
	witnessURL   string
	witnessToken string
	log          *slog.Logger

	// The HA loops start and stop with the stored switch, so a running node
	// can be turned off and on without a restart. stopLife owns the control
	// socket and the watcher; the lease and replication have their own stops.
	mu       sync.Mutex
	stopLife context.CancelFunc
	started  bool
}

// usable reports whether the loops are up, so a move is refused instead of
// starting the runtime halfway through.
func (h *haRuntime) usable() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.started && h.mgr != nil
}

func (h *haRuntime) manager() *ha.Manager {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.mgr
}

// Start brings up the HA loops this role needs. It is idempotent, and it does
// not touch the data plane: turning HA on does not start or stop traffic.
func (h *haRuntime) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.started {
		return nil
	}
	if h.ident == nil {
		ident, err := ha.LoadOrCreateIdentity(h.dir)
		if err != nil {
			return err
		}
		h.ident = ident
	}
	node, err := ha.Load(h.dir)
	if err != nil {
		return err
	}
	life, stop := context.WithCancel(h.root)
	h.stopLife, h.started = stop, true
	if h.mgr == nil {
		h.mgr = ha.NewManager(h.dir, h.hooks())
	}
	if h.witness == nil && h.witnessURL != "" {
		if pair, err := ha.LoadPair(h.dir); err == nil && pair != nil {
			h.witness = &ha.WitnessClient{URL: h.witnessURL, Token: h.witnessToken,
				ClusterID: pair.ClusterID, Holder: h.ident.Node}
		}
	}
	// Capture is what feeds the outbox; a standby must not write to it.
	h.st.SetAuditEnabled(node.Active())
	if node.Active() {
		h.st.SetNodeID(h.ident.Node)
	} else {
		h.repl.Start()
	}
	if err := h.serveControl(life); err != nil {
		h.log.Error("ha control socket failed", "err", err)
	}
	if node.Active() {
		h.startLease(node.Epoch)
	}
	if h.autoFailover {
		h.startAuto(life)
	}
	h.log.Info("high availability started", "role", node.Role)
	return nil
}

// Stop takes the HA loops down and leaves the node serving on its own. A
// standby that is stopped this way is still not serving; a restart is what
// returns it to a single node.
func (h *haRuntime) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.started {
		return
	}
	h.started = false
	h.stopLease()
	if h.stopLife != nil {
		h.stopLife()
		h.stopLife = nil
	}
	h.repl.Stop()
	h.st.SetNodeID("")
	// A stopped standby keeps its audit chain untouched for the next active.
	if node, err := ha.Load(h.dir); err != nil || node.Active() {
		h.st.SetAuditEnabled(true)
	}
	h.quiesce.Set(false)
	h.log.Info("high availability stopped")
}

// peerWatch is the last heartbeat, shared by the probe and the watcher.
type peerWatch struct {
	mu       sync.Mutex
	last     ha.PeerPing
	have     bool
	conflict atomic.Bool
}

func (p *peerWatch) set(ping ha.PeerPing) {
	p.mu.Lock()
	p.last, p.have = ping, true
	p.mu.Unlock()
}

func (p *peerWatch) get() (ha.PeerPing, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.last, p.have
}

// serveControl exposes the move commands on the local Unix socket. Nothing here
// listens on the network: keepalived and `wafproxy ha` run on the node.
func (h *haRuntime) serveControl(ctx context.Context) error {
	path := ha.ControlSocketPath(h.dir)
	if h.mgr == nil {
		h.mgr = ha.NewManager(h.dir, h.hooks())
	}
	if _, err := ha.ServeControl(ctx, path, h.mgr, h.log); err != nil {
		return err
	}
	h.log.Info("ha control socket listening", "path", path)
	return nil
}

func (h *haRuntime) hooks() ha.Hooks {
	return ha.Hooks{
		Preflight:   h.preflight,
		QuiescePeer: func(ctx context.Context) error { return ha.SetPeerQuiesced(ctx, h.dir, true) },
		ResumePeer:  func(ctx context.Context) error { return ha.SetPeerQuiesced(ctx, h.dir, false) },
		Drain:       func(ctx context.Context) error { return ha.Drain(ctx, h.dir, h.st, 15*time.Second) },
		Prebind:     func(ctx context.Context) error { return h.plane.Prebind(ctx) },
		Reload:      h.api.ReloadAll,
		ReconcileBans: func(context.Context) error {
			h.bans.Reconcile()
			return nil
		},
		Serve:            h.serveDataPlane,
		DemotePlane:      h.demoteDataPlane,
		StopReplication:  h.repl.Stop,
		StartReplication: h.repl.Start,
		OnRollback:       h.repl.Start,
		RecheckLease:     h.recheckLease,
	}
}

// recheckLease renews the lease at the epoch that is now on disk, right before
// the data plane serves.
func (h *haRuntime) recheckLease(ctx context.Context) error {
	if h.witness == nil {
		return errors.New("ha: automatic promotion needs a witness")
	}
	node, err := ha.Load(h.dir)
	if err != nil {
		return err
	}
	_, err = h.witness.Acquire(ctx, node.Epoch)
	return err
}

// startAuto watches the peer on both roles. The monitor keeps the last
// heartbeat and raises a conflict when the peer reports a higher epoch; the
// loop promotes only while this node is a standby, so a node that booted
// active keeps its watcher after it steps down.
func (h *haRuntime) startAuto(ctx context.Context) {
	if h.witness == nil || h.mgr == nil {
		h.log.Error("automatic failover needs a witness and the move manager; not starting")
		return
	}
	pair, err := ha.LoadPair(h.dir)
	if err != nil || pair == nil {
		h.log.Error("automatic failover needs a paired node; not starting")
		return
	}
	h.peer = &peerWatch{}
	monitor := ha.NewMonitor(func(ctx context.Context) error {
		ping, err := ha.PingPeer(ctx, h.dir)
		if err != nil {
			return err
		}
		h.peer.set(ping)
		if n, err := ha.Load(h.dir); err == nil && n.Active() && ping.Epoch > n.Epoch {
			h.peer.conflict.Store(true)
		}
		return nil
	})
	fencer := ha.Fencer{Command: h.fence, Peer: pair.PeerAddr}
	h.monitor = monitor
	h.auto = &ha.AutoPromoter{
		Monitor:   monitor,
		LocalNode: h.ident.Node,
		Gather:    h.preflight,
		Peer:      h.peer.get,
		Lease:     h.witness.Acquire,
		Fence:     fencer.Run,
		Promote:   h.mgr.FailoverAuto,
	}
	go monitor.Run(ctx)
	go h.runAuto(ctx)
}

func (h *haRuntime) runAuto(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastReason := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		node, err := ha.Load(h.dir)
		if err != nil {
			continue
		}
		if h.peer.conflict.Swap(false) {
			h.selfDemote(ctx, node)
			continue
		}
		if node.Active() {
			continue
		}
		switch node.EffectiveState() {
		case ha.StateParked, ha.StateFenced:
			continue
		case ha.StateSplitBrainRisk:
			h.tryReconcile(node)
			continue
		}
		if err := h.flap.Check(); err != nil {
			h.park(node, err)
			return
		}
		res, acted, err := h.auto.Step(ctx)
		if err != nil {
			if reason := err.Error(); reason != lastReason {
				h.log.Warn("automatic failover held", "reason", reason)
				lastReason = reason
			}
			continue
		}
		lastReason = ""
		if acted {
			h.flap.Record()
			h.log.Info("automatic failover promoted this node", "epoch", res.Epoch, "steps", len(res.Steps))
		}
	}
}

// selfDemote stops serving after the peer reports a higher epoch. The node
// stays split-brain-risk until the peer is reachable and the epochs settle.
func (h *haRuntime) selfDemote(ctx context.Context, node *ha.Node) {
	ping, _ := h.peer.get()
	h.log.Error("the peer reports a higher epoch; standing down",
		"local_epoch", node.Epoch, "peer_epoch", ping.Epoch)
	if _, err := h.mgr.SelfDemote(ctx); err != nil {
		h.log.Error("self-demotion failed", "err", err)
	}
}

func (h *haRuntime) tryReconcile(node *ha.Node) {
	ping, ok := h.peer.get()
	if !ok || h.monitor == nil || !h.monitor.Health().Reachable || ping.Epoch < node.Epoch {
		return
	}
	if _, err := ha.Reconcile(h.dir, node, ping.Epoch); err != nil {
		h.log.Error("reconcile split-brain-risk", "err", err)
		return
	}
	h.log.Info("split-brain-risk cleared; following the peer", "epoch", ping.Epoch)
	h.repl.Start()
}

// park stops automatic moves for good, until an operator moves by hand.
func (h *haRuntime) park(node *ha.Node, reason error) {
	if _, err := ha.Park(h.dir, node, reason.Error()); err != nil {
		h.log.Error("park the pair", "err", err)
	}
	h.log.Error("automatic failover parked; investigate, then move by hand", "reason", reason)
}

// startLease renews the active's witness lease and demotes it when the lease
// can no longer be held. Without a witness the pair stays on P5's manual moves.
func (h *haRuntime) startLease(epoch int64) {
	if h.witness == nil || h.mgr == nil {
		return
	}
	h.stopLease()
	client := *h.witness
	keeper := ha.NewLeaseKeeper(&client, epoch)
	leaseCtx, cancel := context.WithCancel(h.root)
	h.leaseCancel = cancel
	keeper.OnLoss = func(context.Context) {
		h.log.Error("witness lease lost; demoting this node", "epoch", epoch)
		if _, err := h.mgr.Failback(context.Background(), ha.MoveOptions{}); err != nil {
			h.log.Error("self-demotion after losing the lease failed", "err", err)
		}
	}
	go keeper.Run(leaseCtx)
	h.log.Info("witness lease renewal started", "witness", client.URL, "epoch", epoch)
}

func (h *haRuntime) stopLease() {
	if h.leaseCancel != nil {
		h.leaseCancel()
		h.leaseCancel = nil
	}
}

// preflight answers the checks from this node's own data, plus the peer's cheap
// config version. The peer failing to answer is a check result, not an error.
func (h *haRuntime) preflight(ctx context.Context) (ha.PreflightInput, error) {
	return ha.GatherPreflight(ctx, ha.PreflightSource{
		DataDir: h.dir,
		Store:   h.st,
		MissingCertificates: func() []string {
			list, err := h.all.ListProxies()
			if err != nil {
				return nil
			}
			var missing []string
			for _, p := range list {
				if _, err := h.res.CertificateForHost(p.Hostname); err != nil {
					missing = append(missing, p.Hostname)
					if len(missing) == 10 {
						break
					}
				}
			}
			return missing
		},
		ConfigWriteInFlight: func() bool { return h.api.ConfigWritesInFlight() > 0 },
	})
}

// serveDataPlane is the promotion's point of no return. Capture and audit turn
// on before listeners accept, so the first write under the new epoch is in the
// stream the next standby follows.
func (h *haRuntime) serveDataPlane(ctx context.Context) error {
	h.repl.Stop()
	// A peer may have quiesced this node during the move that made it the
	// standby; that gate must not outlive the promotion.
	h.quiesce.Set(false)
	h.st.SetNodeID(h.ident.Node)
	h.st.SetAuditEnabled(true)
	if err := h.plane.Serve(ctx); err != nil {
		h.st.SetAuditEnabled(false)
		h.st.SetNodeID("")
		return err
	}
	h.active.Start()
	if node, err := ha.Load(h.dir); err == nil {
		h.startLease(node.Epoch)
	}
	return nil
}

// demoteDataPlane stops the loops first, then drains traffic, then gives up
// capture: nothing written after the role file says standby may enter the
// active's stream.
func (h *haRuntime) demoteDataPlane(ctx context.Context) {
	h.stopLease()
	h.active.Stop()
	h.repl.Stop()
	h.plane.Drain(ctx)
	h.st.SetAuditEnabled(false)
	h.st.SetNodeID("")
}
