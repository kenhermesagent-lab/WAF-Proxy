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
	dir    string
	st     *store.Store
	all    *store.Store
	res    *siteres.Set
	bans   *ban.Engine
	api    *api.Server
	plane  *dataPlane
	active *activeSupervisor
	repl   *replicator
	ident  *ha.Identity
	log    *slog.Logger
}

// serveControl exposes the move commands on the local Unix socket. Nothing here
// listens on the network: keepalived and `wafproxy ha` run on the node.
func (h *haRuntime) serveControl(ctx context.Context) error {
	mgr := ha.NewManager(h.dir, h.hooks())
	path := ha.ControlSocketPath(h.dir)
	if _, err := ha.ServeControl(ctx, path, mgr, h.log); err != nil {
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
		Reload: func(ctx context.Context) error {
			return h.api.ReloadAll(ctx)
		},
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
	h.st.SetNodeID(h.ident.Node)
	h.st.SetAuditEnabled(true)
	if err := h.plane.Serve(ctx); err != nil {
		h.st.SetAuditEnabled(false)
		h.st.SetNodeID("")
		return err
	}
	h.active.Start()
	return nil
}

// demoteDataPlane stops the loops first, then drains traffic, then gives up
// capture: nothing written after the role file says standby may enter the
// active's stream.
func (h *haRuntime) demoteDataPlane(ctx context.Context) error {
	h.active.Stop()
	h.repl.Stop()
	err := h.plane.Drain(ctx)
	h.st.SetAuditEnabled(false)
	h.st.SetNodeID("")
	return err
}
