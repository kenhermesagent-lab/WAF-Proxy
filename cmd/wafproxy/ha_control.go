package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/config"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ha"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// haBootOn reports whether this boot runs HA: the environment switch allows it
// and the stored host-wide setting has it on.
func haBootOn(cfg *config.Config, st *store.Store) bool {
	return cfg.HAEnabled && haSettingOn(st)
}

// haBootRole decides the role this boot runs with. A paired node keeps its role
// even while HA is off, so a standby stays out of service; an unpaired leftover
// standby becomes a single node and serves again.
func haBootRole(dir string, node *ha.Node, paired, haOn bool) (*ha.Node, error) {
	if haOn || paired {
		return node, nil
	}
	return ha.MakeStandalone(dir, node)
}

// haDisableRefusal is why turning HA off is refused, or "" when it is allowed.
// A paired standby never serves, and a paired active needs the cluster id typed
// so nobody turns off the only node that can take over by accident.
func haDisableRefusal(node *ha.Node, pair *ha.Pair, confirm string) string {
	if pair == nil {
		return ""
	}
	if !node.Active() {
		return "this node is a paired standby; turning high availability off would take it out of service. Move the service to this node or unpair it first"
	}
	if strings.TrimSpace(confirm) != pair.ClusterID {
		return fmt.Sprintf("this node is paired in cluster %s; with high availability off no node takes over if it fails. Type the cluster id to confirm, or unpair first", pair.ClusterID)
	}
	return ""
}

// flapBudget is the console-set budget when there is one, else the environment
// default. The setting is host-wide; a per-site copy is ignored.
func flapBudget(st *store.Store, fallback int) int {
	raw, err := st.GetSetting("ha_max_failovers_per_hour")
	if err != nil {
		return fallback
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 1 || n > 100 {
		return fallback
	}
	return n
}

// haSettingOn is the stored host-wide switch. Missing means off, so a fresh
// install stays single-node.
func haSettingOn(st *store.Store) bool {
	raw, err := st.GetSetting("ha_enabled")
	return err == nil && raw == "1"
}

// haControl is the console's HA backend. It calls the same move manager and the
// same role files as `wafproxy ha`, so a click cannot take a different path than
// the CLI. Pairing and syncing only need the data directory and the store, so
// they work while the loops are stopped.
type haControl struct {
	dir      string
	st       *store.Store
	fallback int
	rt       *haRuntime
}

func (c haControl) manager() (*ha.Manager, error) {
	if c.rt == nil || !c.rt.usable() {
		return nil, errors.New("high availability is not running on this node")
	}
	return c.rt.manager(), nil
}

func (c haControl) Pair(context.Context) (string, error) {
	if pair, err := ha.LoadPair(c.dir); err != nil {
		return "", err
	} else if pair != nil {
		return "", errors.New("this node is already paired; unpair it first")
	}
	return ha.WritePairingCode(c.dir)
}

func (c haControl) Join(ctx context.Context, addr, fingerprint, code string) error {
	if pair, err := ha.LoadPair(c.dir); err != nil {
		return err
	} else if pair != nil {
		return errors.New("this node is already paired; unpair it first")
	}
	if _, err := ha.Join(ctx, c.dir, addr, fingerprint, code); err != nil {
		return err
	}
	if c.rt != nil && c.rt.usable() {
		c.rt.repl.Start()
	}
	return nil
}

func (c haControl) Sync(ctx context.Context) (ha.SyncResult, error) {
	return ha.SyncOnce(ctx, c.dir, c.st)
}

func (c haControl) Failover(ctx context.Context, opts ha.MoveOptions) (ha.Result, error) {
	m, err := c.manager()
	if err != nil {
		return ha.Result{}, err
	}
	return m.Failover(ctx, opts)
}

func (c haControl) Failback(ctx context.Context, opts ha.MoveOptions) (ha.Result, error) {
	m, err := c.manager()
	if err != nil {
		return ha.Result{}, err
	}
	return m.Failback(ctx, opts)
}

func (c haControl) Unpair(context.Context) error {
	if err := ha.Unpair(c.dir); err != nil {
		return err
	}
	if c.rt != nil {
		c.rt.repl.Stop()
		c.rt.quiesce.Set(false)
	}
	return nil
}

// Notify is the keepalived mapping: MASTER promotes, BACKUP and FAULT stand the
// node down. A refusal is an error so the caller sees why.
func (c haControl) Notify(ctx context.Context, role string) (ha.Result, error) {
	switch strings.ToUpper(strings.TrimSpace(role)) {
	case "MASTER":
		return c.Failover(ctx, ha.MoveOptions{})
	case "BACKUP", "FAULT":
		return c.Failback(ctx, ha.MoveOptions{})
	}
	return ha.Result{}, fmt.Errorf("unknown keepalived role %q", role)
}

func (c haControl) MaxFailovers() int {
	if c.rt != nil {
		return c.rt.flap.Maximum()
	}
	return flapBudget(c.st, c.fallback)
}

func (c haControl) SetMaxFailovers(n int) error {
	if c.rt == nil {
		return nil
	}
	return c.rt.flap.SetMax(n)
}
