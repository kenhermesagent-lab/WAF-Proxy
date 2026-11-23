package ha

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Hooks are the side effects of a move. The sequence owns the order and the
// role file; the process owns listeners, engines, replication and the kernel.
type Hooks struct {
	Preflight        func(context.Context) (PreflightInput, error)
	QuiescePeer      func(context.Context) error
	ResumePeer       func(context.Context) error
	Drain            func(context.Context) error
	Prebind          func(context.Context) error
	Reload           func(context.Context) error
	ReconcileBans    func(context.Context) error
	Serve            func(context.Context) error
	DemotePlane      func(context.Context)
	StopReplication  func()
	StartReplication func()
	// OnRollback undoes process-side work after a move gave up, such as
	// restarting the stream follower a promotion had stopped.
	OnRollback func()
	// AutoChecks supplies the evidence for an unattended move. PromoteWith
	// uses it instead of Preflight when the move is automatic.
	AutoChecks func(context.Context) (AutoInput, error)
	// RecheckLease renews the witness lease immediately before the data plane
	// serves, so a slow promotion cannot outlive its lease.
	RecheckLease func(context.Context) error
}

// Step records one step of a move. A failed step stays in the list, so a
// refused or aborted move says exactly where it stopped.
type Step struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	Millis int64  `json:"ms"`
	At     string `json:"at"`
}

// Result is the outcome of a move, including the checks that gated it.
type Result struct {
	DryRun     bool     `json:"dry_run"`
	Epoch      int64    `json:"epoch"`
	Checks     []Check  `json:"checks,omitempty"`
	Steps      []Step   `json:"steps,omitempty"`
	Overridden []string `json:"overridden,omitempty"`
	DurationMS int64    `json:"duration_ms"`
}

// BlockedError is a refusal: nothing changed, and the named check says why.
type BlockedError struct {
	Check Check
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("ha: preflight failed at %s: %s", e.Check.Name, e.Check.Detail)
}

// Promote moves a standby to active. The order is the plan's: the peer stops
// writing, this node drains its stream, the epoch is persisted, the data plane
// is prepared, and only then are listeners served. Every step before Serve is
// reversible; a failure returns the node to standby.
func Promote(ctx context.Context, dataDir string, hooks Hooks, force, dryRun bool) (Result, error) {
	return PromoteWith(ctx, dataDir, hooks, PromoteOptions{Force: force, DryRun: dryRun})
}

// PromoteOptions selects the manual or the unattended sequence.
//
// Auto skips quiescing and draining the peer: an unattended move starts because
// the peer is unreachable, so those steps can only fail. The gate that replaces
// them is EvaluateAuto, and the lease is renewed once more before Serve.
type PromoteOptions struct {
	Force  bool
	DryRun bool
	Auto   bool
}

// PromoteWith is Promote with the auto gate available.
func PromoteWith(ctx context.Context, dataDir string, hooks Hooks, opts PromoteOptions) (Result, error) {
	res := Result{DryRun: opts.DryRun}
	started := time.Now()
	node, err := Load(dataDir)
	if err != nil {
		return res, err
	}
	res.Epoch = node.Epoch
	if node.Role != RoleStandby {
		return res, fmt.Errorf("ha: only a standby can be promoted (this node is %s)", node.Role)
	}
	if opts.Auto {
		if hooks.AutoChecks == nil {
			return res, errors.New("ha: automatic promotion has no preflight")
		}
		in, err := hooks.AutoChecks(ctx)
		if err != nil {
			return res, err
		}
		res.Checks = EvaluateAuto(in)
		if fail := FirstFailure(res.Checks); fail != nil {
			res.DurationMS = time.Since(started).Milliseconds()
			if !opts.Force {
				return res, &BlockedError{Check: *fail}
			}
			res.Overridden = append(res.Overridden, fail.Name)
		}
	} else {
		if hooks.Preflight == nil {
			return res, errors.New("ha: no preflight source")
		}
		in, err := hooks.Preflight(ctx)
		if err != nil {
			return res, err
		}
		res.Checks = EvaluatePreflight(in)
	}
	if opts.DryRun {
		res.DurationMS = time.Since(started).Milliseconds()
		if fail := FirstFailure(res.Checks); fail != nil {
			return res, &BlockedError{Check: *fail}
		}
		return res, nil
	}
	epoch := node.Epoch + 1

	if !opts.Auto {
		// 1. The peer stops accepting new writes, so what follows is a stable copy.
		if hooks.QuiescePeer != nil {
			if err := record(ctx, &res, "quiesce-peer", func() error { return hooks.QuiescePeer(ctx) }); err != nil {
				if !opts.Force {
					return res, err
				}
				res.Overridden = append(res.Overridden, "quiesce-peer")
			}
		}
		// 2. Follow the peer's stream to its head.
		if hooks.Drain != nil {
			if err := record(ctx, &res, "drain", func() error { return hooks.Drain(ctx) }); err != nil {
				if !opts.Force {
					resumePeer(hooks)
					res.DurationMS = time.Since(started).Milliseconds()
					return res, err
				}
				res.Overridden = append(res.Overridden, "drain")
			}
		}
		// 3. Preflight again: hash and lag only mean something once the stream is
		// at its head.
		in, err := hooks.Preflight(ctx)
		if err != nil {
			resumePeer(hooks)
			return res, err
		}
		res.Checks = EvaluatePreflight(in)
		if fail := FirstFailure(res.Checks); fail != nil {
			resumePeer(hooks)
			res.DurationMS = time.Since(started).Milliseconds()
			if !opts.Force {
				return res, &BlockedError{Check: *fail}
			}
			res.Overridden = append(res.Overridden, fail.Name)
		}
	}
	// 4. The epoch reaches disk before any listener can accept under it. A crash
	// from here on restarts as a promoting standby, never an old active.
	role, err := BeginPromotion(dataDir, node, epoch)
	if err != nil {
		resumeAfter(hooks, opts.Auto)
		return res, err
	}
	res.Epoch = epoch
	addStep(&res, "epoch", true, fmt.Sprintf("epoch %d persisted", epoch), 0)
	rollback := func() {
		_, _ = ReturnToStandby(dataDir, role)
		resumeAfter(hooks, opts.Auto)
	}
	for _, s := range []struct {
		name string
		fn   func(context.Context) error
	}{
		{"prebind", hooks.Prebind},
		{"reload", hooks.Reload},
		{"reconcile-bans", hooks.ReconcileBans},
	} {
		if s.fn == nil {
			continue
		}
		fn := s.fn
		if err := record(ctx, &res, s.name, func() error { return fn(ctx) }); err != nil {
			rollback()
			res.DurationMS = time.Since(started).Milliseconds()
			return res, err
		}
	}
	// The lease is renewed at the epoch that is now on disk. An unattended move
	// that took longer than the TTL must fail here, not serve without one.
	if opts.Auto && hooks.RecheckLease != nil {
		if err := record(ctx, &res, "lease", func() error { return hooks.RecheckLease(ctx) }); err != nil {
			rollback()
			res.DurationMS = time.Since(started).Milliseconds()
			return res, err
		}
	}
	// 5. Serving is the point of no return. Once listeners accept, an abort is
	// a failback, not a cancellation.
	if hooks.Serve != nil {
		if err := record(ctx, &res, "serve", func() error { return hooks.Serve(ctx) }); err != nil {
			rollback()
			res.DurationMS = time.Since(started).Milliseconds()
			return res, err
		}
	}
	if _, err := Activate(dataDir, role, epoch); err != nil {
		return res, err
	}
	addStep(&res, "activate", true, fmt.Sprintf("epoch %d active", epoch), 0)
	res.DurationMS = time.Since(started).Milliseconds()
	return res, nil
}

// Demote steps an active node down. Listeners close before the role file says
// standby, so a crash in between never leaves a standby that still answers.
func Demote(ctx context.Context, dataDir string, hooks Hooks) (Result, error) {
	return demote(ctx, dataDir, hooks, StateStandby)
}

// SelfDemote is Demote for an active node that observed a higher epoch. It
// stops serving and stays split-brain-risk, and it does not start replication:
// the node must reconcile with the peer before it follows it.
func SelfDemote(ctx context.Context, dataDir string, hooks Hooks) (Result, error) {
	return demote(ctx, dataDir, hooks, StateSplitBrainRisk)
}

func demote(ctx context.Context, dataDir string, hooks Hooks, state State) (Result, error) {
	res := Result{}
	node, err := Load(dataDir)
	if err != nil {
		return res, err
	}
	res.Epoch = node.Epoch
	if node.Role != RoleActive {
		return res, fmt.Errorf("ha: only an active node can step down (this node is %s)", node.Role)
	}
	if hooks.StopReplication != nil {
		hooks.StopReplication()
	}
	if hooks.DemotePlane != nil {
		if err := record(ctx, &res, "drain-listeners", func() error { hooks.DemotePlane(ctx); return nil }); err != nil {
			return res, err
		}
	}
	role, err := EnterState(dataDir, node, state)
	if err != nil {
		return res, err
	}
	res.Epoch = role.Epoch
	addStep(&res, "role", true, string(state), 0)
	if state == StateStandby && hooks.StartReplication != nil {
		hooks.StartReplication()
	}
	return res, nil
}

func record(ctx context.Context, res *Result, name string, fn func() error) error {
	if err := ctx.Err(); err != nil {
		addStep(res, name, false, "cancelled", 0)
		return err
	}
	started := time.Now()
	err := fn()
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	addStep(res, name, err == nil, detail, time.Since(started))
	return err
}

func addStep(res *Result, name string, ok bool, detail string, dur time.Duration) {
	res.Steps = append(res.Steps, Step{
		Name: name, OK: ok, Detail: detail,
		Millis: dur.Milliseconds(), At: time.Now().UTC().Format(time.RFC3339),
	})
}

// resumePeer reopens the peer's write gate. It runs on a fresh context: the
// move's context may be the thing that was cancelled.
func resumePeer(hooks Hooks) { resumeAfter(hooks, false) }

// resumeAfter reopens the peer's write gate, unless the move was automatic and
// the peer is exactly what is unreachable.
func resumeAfter(hooks Hooks, peerDown bool) {
	if hooks.OnRollback != nil {
		hooks.OnRollback()
	}
	if peerDown || hooks.ResumePeer == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = hooks.ResumePeer(ctx)
}
