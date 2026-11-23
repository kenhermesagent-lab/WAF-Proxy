package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ha"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

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

// haControl is the console's HA backend. It calls the same move manager and the
// same role files as `wafproxy ha`, so a click cannot take a different path than
// the CLI.
type haControl struct{ rt *haRuntime }

func (c haControl) manager() (*ha.Manager, error) {
	if c.rt.mgr == nil {
		return nil, errors.New("the HA control socket is not running on this node")
	}
	return c.rt.mgr, nil
}

func (c haControl) Pair(context.Context) (string, error) {
	if pair, err := ha.LoadPair(c.rt.dir); err != nil {
		return "", err
	} else if pair != nil {
		return "", errors.New("this node is already paired; unpair it first")
	}
	return ha.WritePairingCode(c.rt.dir)
}

func (c haControl) Join(ctx context.Context, addr, fingerprint, code string) error {
	if pair, err := ha.LoadPair(c.rt.dir); err != nil {
		return err
	} else if pair != nil {
		return errors.New("this node is already paired; unpair it first")
	}
	if _, err := ha.Join(ctx, c.rt.dir, addr, fingerprint, code); err != nil {
		return err
	}
	c.rt.repl.Start()
	return nil
}

func (c haControl) Sync(ctx context.Context) (ha.SyncResult, error) {
	return ha.SyncOnce(ctx, c.rt.dir, c.rt.st)
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
	if err := ha.Unpair(c.rt.dir); err != nil {
		return err
	}
	c.rt.repl.Stop()
	c.rt.quiesce.Set(false)
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

func (c haControl) MaxFailovers() int { return c.rt.flap.Maximum() }

func (c haControl) SetMaxFailovers(n int) error { return c.rt.flap.SetMax(n) }
