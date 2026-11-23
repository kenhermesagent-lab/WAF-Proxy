package ha

import (
	"context"
	"fmt"
)

// AutoInput is the evidence an unattended promotion runs on. It is separate
// from PreflightInput because two of the checks are inverted: an automatic move
// needs the peer to be unreachable, and the witness and fence replace the
// operator's judgement.
type AutoInput struct {
	// Preflight carries the local facts (schema, epoch, database, disk,
	// certificates, in-flight writes).
	Preflight PreflightInput
	// LocalNode is this node's identity, matched against the lease holder.
	LocalNode string
	// PeerDown is the heartbeat's decision, not one missed beat.
	PeerDown bool
	// LastPeer is the last successful heartbeat, used where a live peer cannot
	// be asked.
	LastPeer *PeerPing
	// Lease is the witness's answer for the next epoch.
	Lease    *Lease
	LeaseErr string
	// FenceRan records that a fence command exists and was executed.
	FenceRan bool
	FenceErr error
}

// EvaluateAuto is P6-04: the manual preflight minus the checks that need a live
// peer, plus the three pieces that make an unattended move safe. Hash and lag
// are absent because they can only be read from the peer; the stream and the
// witness cover them instead.
func EvaluateAuto(in AutoInput) []Check {
	return []Check{
		autoPeerDown(in),
		autoBaseline(in),
		autoLease(in),
		autoFence(in),
		autoSchema(in),
		autoProtocol(in),
		autoEpoch(in),
		checkCertificates(in.Preflight),
		checkDatabase(in.Preflight),
		checkDisk(in.Preflight),
		checkConfigWrite(in.Preflight),
	}
}

func autoPeerDown(in AutoInput) Check {
	c := Check{Name: "peer-down"}
	if in.PeerDown {
		c.OK = true
		c.Detail = "the heartbeat has declared the peer unreachable"
		return c
	}
	c.Detail = "the peer is still answering the heartbeat"
	c.Fix = "wait for three lost beats, or run `wafproxy ha failover` deliberately"
	return c
}

func autoBaseline(in AutoInput) Check {
	c := Check{Name: "peer-baseline"}
	if in.LastPeer != nil {
		c.OK = true
		c.Detail = fmt.Sprintf("the last heartbeat put the peer at epoch %d", in.LastPeer.Epoch)
		return c
	}
	c.Detail = "no heartbeat has ever succeeded, so the peer's version and epoch are unknown"
	c.Fix = "restore the HA link and let one heartbeat succeed before relying on automatic failover"
	return c
}

func autoLease(in AutoInput) Check {
	c := Check{Name: "lease"}
	want := in.Preflight.LocalEpoch + 1
	switch {
	case in.LeaseErr != "":
		c.Detail = "the witness did not grant a lease: " + in.LeaseErr
		c.Fix = "check the witness address and token; an automatic move never runs without a lease"
	case in.Lease == nil:
		c.Detail = "no witness lease was requested"
		c.Fix = "configure WAFPROXY_HA_WITNESS and WAFPROXY_HA_WITNESS_TOKEN"
	case !in.Lease.Granted:
		c.Detail = "the witness refused the lease"
		c.Fix = "another node may still hold the epoch; investigate before forcing a move"
	case in.Lease.Holder != in.LocalNode:
		c.Detail = fmt.Sprintf("the lease is held by %s, not this node", in.Lease.Holder)
		c.Fix = "stop the other node first; two holders is the split brain the witness exists to prevent"
	case in.Lease.Epoch != want:
		c.Detail = fmt.Sprintf("the lease is for epoch %d, the move needs %d", in.Lease.Epoch, want)
		c.Fix = "retry: the witness and the role file disagree about the next epoch"
	default:
		c.OK = true
		c.Detail = fmt.Sprintf("this node holds epoch %d until %s", in.Lease.Epoch, in.Lease.ExpiresAt)
	}
	return c
}

func autoFence(in AutoInput) Check {
	c := Check{Name: "fence"}
	switch {
	case !in.FenceRan:
		c.Detail = "no fence command ran"
		c.Fix = "set WAFPROXY_HA_FENCE_COMMAND; an automatic move is refused without proof the peer is down"
	case in.FenceErr != nil:
		c.Detail = in.FenceErr.Error()
		c.Fix = "fix the fence script or fence the peer by hand, then retry"
	default:
		c.OK = true
		c.Detail = "the fence command reported the peer down"
	}
	return c
}

func autoSchema(in AutoInput) Check {
	c := Check{Name: "schema"}
	if in.LastPeer == nil || in.LastPeer.Schema == "" {
		c.Detail = "the peer's last heartbeat did not report a schema"
		c.Fix = "upgrade both nodes to the same release"
		return c
	}
	if in.Preflight.LocalSchema != in.LastPeer.Schema {
		c.Detail = fmt.Sprintf("schema %s does not match the peer's last known %s", in.Preflight.LocalSchema, in.LastPeer.Schema)
		c.Fix = "upgrade the standby first, then the active"
		return c
	}
	c.OK = true
	c.Detail = "schema " + in.Preflight.LocalSchema + " matches the peer's last heartbeat"
	return c
}

func autoProtocol(in AutoInput) Check {
	c := Check{Name: "protocol"}
	if in.LastPeer == nil || in.LastPeer.Protocol != in.Preflight.LocalProtocol {
		c.Detail = "the link protocol does not match the peer's last heartbeat"
		c.Fix = "both nodes must run the same release"
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("protocol %d matches the peer's last heartbeat", in.Preflight.LocalProtocol)
	return c
}

func autoEpoch(in AutoInput) Check {
	c := Check{Name: "epoch"}
	if in.LastPeer != nil && in.LastPeer.Epoch > in.Preflight.LocalEpoch {
		c.Detail = fmt.Sprintf("the peer was at epoch %d, this node at %d", in.LastPeer.Epoch, in.Preflight.LocalEpoch)
		c.Fix = "this node is behind; let it sync before it takes over"
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("this node is at epoch %d, the peer's last at %d", in.Preflight.LocalEpoch, lastEpoch(in.LastPeer))
	return c
}

func lastEpoch(p *PeerPing) int64 {
	if p == nil {
		return 0
	}
	return p.Epoch
}

// AutoPromoter runs the unattended path. Its inputs are functions so a test can
// drive the whole decision without a peer, a witness or a fence script.
type AutoPromoter struct {
	Monitor    *Monitor
	LocalNode  string
	LocalEpoch func() int64
	Gather     func(context.Context) (PreflightInput, error)
	Peer       func() (PeerPing, bool)
	Lease      func(context.Context, int64) (Lease, error)
	Fence      func(context.Context) error
	Promote    func(context.Context, AutoInput) (Result, error)
}

// Step makes one automatic decision. It returns promoted=false without an
// error while the heartbeat still considers the peer reachable.
func (a *AutoPromoter) Step(ctx context.Context) (Result, bool, error) {
	if a.Monitor == nil || a.Monitor.Health().Reachable {
		return Result{}, false, nil
	}
	local, err := a.Gather(ctx)
	if err != nil {
		return Result{}, false, err
	}
	in := AutoInput{Preflight: local, LocalNode: a.LocalNode, PeerDown: true}
	if a.Peer != nil {
		if ping, ok := a.Peer(); ok {
			in.LastPeer = &ping
		}
	}
	if a.Lease != nil {
		lease, err := a.Lease(ctx, local.LocalEpoch+1)
		if err != nil {
			in.LeaseErr = err.Error()
		} else {
			in.Lease = &lease
		}
	} else {
		in.LeaseErr = "no witness is configured"
	}
	if a.Fence != nil {
		in.FenceRan = true
		in.FenceErr = a.Fence(ctx)
	}
	checks := EvaluateAuto(in)
	res := Result{Checks: checks, Epoch: local.LocalEpoch}
	if fail := FirstFailure(checks); fail != nil {
		return res, false, &BlockedError{Check: *fail}
	}
	out, err := a.Promote(ctx, in)
	return out, err == nil, err
}
