package main

import (
	"context"
	"log/slog"
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
	log         *slog.Logger
}

// serveControl exposes the move commands on the local Unix socket. Nothing here
// listens on the network: keepalived and `wafproxy ha` run on the node.
func (h *haRuntime) serveControl(ctx context.Context) error {
	path := ha.ControlSocketPath(h.dir)
	h.mgr = ha.NewManager(h.dir, h.hooks())
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
	}
}

// startLease renews the active's witness lease and demotes it when the lease
// can no longer be held. Without a witness the pair stays on P5's manual moves.
func (h *haRuntime) startLease(ctx context.Context, epoch int64) {
	if h.witness == nil || h.mgr == nil {
		return
	}
	h.stopLease()
	client := *h.witness
	keeper := ha.NewLeaseKeeper(&client, epoch)
	leaseCtx, cancel := context.WithCancel(ctx)
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
		h.startLease(ctx, node.Epoch)
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
