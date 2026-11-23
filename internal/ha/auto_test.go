package ha

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func goodAuto() AutoInput {
	in := AutoInput{
		Preflight: goodPreflight(),
		LocalNode: "node-a",
		PeerDown:  true,
		LastPeer: &PeerPing{
			OK: true, Node: "node-b", Role: RoleActive, State: StateActive,
			Epoch: 9, Schema: "25", Protocol: ProtocolVersion,
		},
		Lease: &Lease{
			Granted: true, ClusterID: "cluster-1", Epoch: 10, Holder: "node-a",
			ExpiresAt: time.Now().Add(LeaseTTL).UTC().Format(time.RFC3339Nano),
		},
		FenceRan: true,
	}
	in.Preflight.LocalEpoch = 9
	return in
}

func TestAutoGatePassesOnFullEvidence(t *testing.T) {
	checks := EvaluateAuto(goodAuto())
	if len(checks) != 11 {
		t.Fatalf("auto gate returned %d checks, want 11", len(checks))
	}
	for _, c := range checks {
		if !c.OK {
			t.Fatalf("check %s failed on complete evidence: %s", c.Name, c.Detail)
		}
	}
}

func TestAutoGateBlocksOneCheckAtATime(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*AutoInput)
	}{
		{"peer-down", func(in *AutoInput) { in.PeerDown = false }},
		{"peer-baseline", func(in *AutoInput) { in.LastPeer = nil }},
		{"lease", func(in *AutoInput) { in.Lease = nil }},
		{"lease", func(in *AutoInput) { in.LeaseErr = "witness unreachable" }},
		{"lease", func(in *AutoInput) { in.Lease.Granted = false }},
		{"lease", func(in *AutoInput) { in.Lease.Holder = "node-b" }},
		{"lease", func(in *AutoInput) { in.Lease.Epoch = 11 }},
		{"lease", func(in *AutoInput) { in.Lease.Epoch = 9 }},
		{"fence", func(in *AutoInput) { in.FenceRan = false }},
		{"fence", func(in *AutoInput) { in.FenceErr = errors.New("exit status 1") }},
		{"schema", func(in *AutoInput) { in.LastPeer.Schema = "24" }},
		{"schema", func(in *AutoInput) { in.LastPeer.Schema = "" }},
		{"protocol", func(in *AutoInput) { in.LastPeer.Protocol = ProtocolVersion + 1 }},
		{"epoch", func(in *AutoInput) { in.LastPeer.Epoch = 10 }},
		{"certificates", func(in *AutoInput) { in.Preflight.MissingCertificates = []string{"shop.example"} }},
		{"database", func(in *AutoInput) { in.Preflight.DatabaseWritable = false }},
		{"database", func(in *AutoInput) { in.Preflight.QuickCheck = "corrupt" }},
		{"disk", func(in *AutoInput) { in.Preflight.DiskFreePercent = 1 }},
		{"config-write", func(in *AutoInput) { in.Preflight.ConfigWriteInFlight = true }},
	}
	for _, tc := range cases {
		in := goodAuto()
		tc.mutate(&in)
		fail := FirstFailure(EvaluateAuto(in))
		if fail == nil {
			t.Fatalf("%s: no check failed", tc.name)
		}
		if fail.Name != tc.name {
			t.Fatalf("expected %s first, got %s (%s)", tc.name, fail.Name, fail.Detail)
		}
		if fail.Fix == "" {
			t.Fatalf("%s blocked without a fix", tc.name)
		}
	}
}

func trippedMonitor(t *testing.T) *Monitor {
	t.Helper()
	m := NewMonitor(func(context.Context) error { return errors.New("no answer") })
	for i := 0; i < m.Threshold; i++ {
		m.Beat(context.Background())
	}
	if m.Health().Reachable {
		t.Fatal("the monitor did not trip")
	}
	return m
}

func autoPromoter(t *testing.T, m *Monitor, promoted *bool, mutate func(*AutoPromoter)) *AutoPromoter {
	t.Helper()
	ap := &AutoPromoter{
		Monitor:    m,
		LocalNode:  "node-a",
		LocalEpoch: func() int64 { return 9 },
		Gather: func(context.Context) (PreflightInput, error) {
			in := goodPreflight()
			in.LocalEpoch = 9
			return in, nil
		},
		Peer: func() (PeerPing, bool) {
			return PeerPing{Epoch: 9, Schema: "25", Protocol: ProtocolVersion}, true
		},
		Lease: func(_ context.Context, epoch int64) (Lease, error) {
			return Lease{Granted: true, Epoch: epoch, Holder: "node-a"}, nil
		},
		Fence: func(context.Context) error { return nil },
		Promote: func(context.Context, AutoInput) (Result, error) {
			if promoted != nil {
				*promoted = true
			}
			return Result{}, nil
		},
	}
	if mutate != nil {
		mutate(ap)
	}
	return ap
}

func TestAutoPromoterWaitsForTheDecision(t *testing.T) {
	failing := true
	m := NewMonitor(func(context.Context) error {
		if failing {
			return errors.New("no answer")
		}
		return nil
	})
	m.Beat(context.Background())
	m.Beat(context.Background())
	promoted := false
	ap := autoPromoter(t, m, &promoted, nil)

	if _, acted, err := ap.Step(context.Background()); acted || err != nil {
		t.Fatalf("acted after two lost beats: acted=%v err=%v", acted, err)
	}
	m.Beat(context.Background())
	if _, acted, err := ap.Step(context.Background()); !acted || err != nil {
		t.Fatalf("the third beat did not promote: acted=%v err=%v", acted, err)
	}
	if !promoted {
		t.Fatal("Step reported a promotion without calling Promote")
	}
}

func TestPromoteAutoSkipsTheDeadPeerAndRechecksTheLease(t *testing.T) {
	dir := t.TempDir()
	roleFor(t, dir, RoleStandby, 9)
	in := goodAuto()
	quiesced, served, leaseChecked := false, false, false
	res, err := PromoteWith(context.Background(), dir, Hooks{
		Preflight: func(context.Context) (PreflightInput, error) {
			return PreflightInput{}, errors.New("the peer is down")
		},
		AutoChecks:  func(context.Context) (AutoInput, error) { return in, nil },
		QuiescePeer: func(context.Context) error { quiesced = true; return errors.New("peer down") },
		Drain:       func(context.Context) error { return errors.New("peer down") },
		Serve:       func(context.Context) error { served = true; return nil },
		RecheckLease: func(context.Context) error {
			leaseChecked = true
			return nil
		},
	}, PromoteOptions{Auto: true})
	if err != nil {
		t.Fatal(err)
	}
	if quiesced {
		t.Fatal("an automatic move tried to quiesce a peer that is down")
	}
	if !served || !leaseChecked {
		t.Fatalf("served=%v leaseChecked=%v", served, leaseChecked)
	}
	if res.Epoch != 10 {
		t.Fatalf("epoch = %d, want 10", res.Epoch)
	}
	node, _ := Load(dir)
	if node.Role != RoleActive || node.Epoch != 10 {
		t.Fatalf("role after an automatic promotion = %+v", node)
	}
}

func TestPromoteAutoRollsBackWhenTheLeaseExpired(t *testing.T) {
	dir := t.TempDir()
	roleFor(t, dir, RoleStandby, 9)
	served := false
	_, err := PromoteWith(context.Background(), dir, Hooks{
		AutoChecks: func(context.Context) (AutoInput, error) { return goodAuto(), nil },
		Serve:      func(context.Context) error { served = true; return nil },
		RecheckLease: func(context.Context) error {
			return errors.New("the lease expired during the move")
		},
	}, PromoteOptions{Auto: true})
	if err == nil || !strings.Contains(err.Error(), "lease expired") {
		t.Fatalf("expired-lease promotion = %v", err)
	}
	if served {
		t.Fatal("the data plane served without a valid lease")
	}
	node, _ := Load(dir)
	if node.Role != RoleStandby {
		t.Fatalf("role after a lease failure = %+v", node)
	}
}

func TestManagerSerialisesAutomaticMoves(t *testing.T) {
	dir := t.TempDir()
	roleFor(t, dir, RoleStandby, 9)
	started := make(chan struct{})
	m := NewManager(dir, Hooks{
		Serve: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		},
		RecheckLease: func(context.Context) error { return nil },
	})
	done := make(chan error, 1)
	go func() {
		_, err := m.FailoverAuto(context.Background(), goodAuto())
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("the automatic move never reached Serve")
	}
	if _, err := m.FailoverAuto(context.Background(), goodAuto()); err == nil || !strings.Contains(err.Error(), "already in progress") {
		t.Fatalf("a second automatic move = %v", err)
	}
	if err := m.Abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("aborted automatic move = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("abort did not stop the automatic move")
	}
	if node, _ := Load(dir); node.Role != RoleStandby {
		t.Fatalf("aborted automatic move left role %+v", node)
	}
}

func TestAutoPromoterRefusesWithoutLeaseOrFence(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*AutoPromoter)
		want   string
	}{
		{"lease", func(a *AutoPromoter) {
			a.Lease = func(context.Context, int64) (Lease, error) { return Lease{}, errors.New("refused") }
		}, "lease"},
		{"fence", func(a *AutoPromoter) {
			a.Fence = func(context.Context) error { return errors.New("exit status 1") }
		}, "fence"},
		{"fence", func(a *AutoPromoter) { a.Fence = nil }, "fence"},
		{"baseline", func(a *AutoPromoter) { a.Peer = func() (PeerPing, bool) { return PeerPing{}, false } }, "peer-baseline"},
	}
	for _, tc := range cases {
		promoted := false
		ap := autoPromoter(t, trippedMonitor(t), &promoted, tc.mutate)
		_, acted, err := ap.Step(context.Background())
		if acted || promoted {
			t.Fatalf("%s: the gate promoted anyway", tc.name)
		}
		var blocked *BlockedError
		if !errors.As(err, &blocked) || blocked.Check.Name != tc.want {
			t.Fatalf("%s: blocked with %v, want %s", tc.name, err, tc.want)
		}
		if !strings.Contains(err.Error(), blocked.Check.Detail) {
			t.Fatalf("%s: error does not carry the reason: %v", tc.name, err)
		}
	}
}
