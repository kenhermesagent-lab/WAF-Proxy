package ha

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// The partition simulator drives the real state machine, heartbeat, witness and
// flap guard on a fake clock. Two role directories on disk are the whole cluster;
// the only thing that makes a node "active" is its role file, exactly as in
// production. Every scenario ends by asserting that at most one live node
// reports itself active.
type simClock struct{ now time.Time }

func (c *simClock) Now() time.Time { return c.now }

func (c *simClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

type simNode struct {
	name       string
	dir        string
	alive      bool
	fence      bool // the fence command runs and the peer really stops
	diskFull   bool
	witness    *Witness
	mon        *Monitor
	guard      *FlapGuard
	ping       PeerPing
	havePing   bool
	promotions int
}

type simCluster struct {
	t     *testing.T
	clock *simClock
	nodes []*simNode
	link  bool
}

const simClusterID = "sim-cluster"

// newSim starts a paired cluster: node A active at epoch 9, node B standby. The
// link is up, so the first tick gives both nodes a baseline heartbeat, which the
// gate requires before it will ever act.
func newSim(t *testing.T, sharedWitness bool) *simCluster {
	t.Helper()
	c := &simCluster{t: t, clock: &simClock{now: time.Unix(1_700_000_000, 0)}, link: true}
	var shared *Witness
	if sharedWitness {
		shared = NewWitness("token")
		shared.now = c.clock.Now
	}
	for i, name := range []string{"node-a", "node-b"} {
		dir := t.TempDir()
		role := RoleStandby
		if i == 0 {
			role = RoleActive
		}
		if err := Save(dir, &Node{NodeID: name, Role: role, Epoch: 9}); err != nil {
			t.Fatal(err)
		}
		n := &simNode{name: name, dir: dir, alive: true, fence: true, guard: NewFlapGuard(3)}
		n.guard.Now = c.clock.Now
		if shared != nil {
			n.witness = shared
		}
		n.mon = NewMonitor(func(context.Context) error { return c.probe(n) })
		n.mon.Now = c.clock.Now
		c.nodes = append(c.nodes, n)
	}
	if !sharedWitness {
		// Each node gets its own witness; this is the split-witness fault.
		for _, n := range c.nodes {
			w := NewWitness("token")
			w.now = c.clock.Now
			n.witness = w
		}
	}
	return c
}

func (c *simCluster) peer(n *simNode) *simNode {
	if c.nodes[0] == n {
		return c.nodes[1]
	}
	return c.nodes[0]
}

// probe is one heartbeat: it reads the peer's real role file, so a promotion on
// the other side is visible on the next beat.
func (c *simCluster) probe(n *simNode) error {
	peer := c.peer(n)
	if !c.link || !peer.alive {
		return errors.New("the peer does not answer")
	}
	node, err := Load(peer.dir)
	if err != nil {
		return err
	}
	n.ping = PeerPing{
		OK: true, Node: peer.name, Role: node.Role, State: node.EffectiveState(),
		Epoch: node.Epoch, Schema: "sim", Protocol: ProtocolVersion,
		Time: c.clock.Now().UTC().Format(time.RFC3339),
	}
	n.havePing = true
	return nil
}

// tick advances the fake clock, runs one heartbeat per live node and makes that
// node's decision.
func (c *simCluster) tick() {
	c.clock.Advance(time.Second)
	for _, n := range c.nodes {
		if !n.alive {
			continue
		}
		n.mon.Beat(context.Background())
		c.act(n)
	}
	c.checkAtMostOneActive()
}

func (c *simCluster) act(n *simNode) {
	node, err := Load(n.dir)
	if err != nil {
		c.t.Fatal(err)
	}
	if node.Active() {
		// An active renews its lease every tick, like the lease keeper.
		if n.witness != nil {
			n.witness.acquire(leaseRequest{ClusterID: simClusterID, Epoch: node.Epoch, Holder: n.name})
		}
		// P6-05: a peer at a higher epoch means this node must stop serving now.
		if n.havePing && c.link && n.ping.Epoch > node.Epoch {
			if _, err := SelfDemote(context.Background(), n.dir, Hooks{}); err != nil {
				c.t.Fatalf("self-demote %s: %v", n.name, err)
			}
		}
		return
	}
	switch node.EffectiveState() {
	case StateSplitBrainRisk:
		if n.havePing && c.link && n.ping.Epoch >= node.Epoch {
			if _, err := Reconcile(n.dir, node, n.ping.Epoch); err != nil {
				c.t.Fatalf("reconcile %s: %v", n.name, err)
			}
		}
		return
	case StateParked, StateFenced:
		return
	}
	if err := n.guard.Check(); err != nil {
		if _, err := Park(n.dir, node, err.Error()); err != nil {
			c.t.Fatalf("park %s: %v", n.name, err)
		}
		return
	}
	if n.mon.Health().Reachable {
		return
	}
	in := AutoInput{
		Preflight: PreflightInput{
			LocalEpoch: node.Epoch, LocalSchema: "sim", LocalProtocol: ProtocolVersion,
			DatabaseWritable: !n.diskFull, QuickCheck: "ok", DiskFreePercent: 100,
		},
		LocalNode: n.name, PeerDown: true,
	}
	if n.diskFull {
		in.Preflight.DiskFreePercent = 1
	}
	if n.havePing {
		ping := n.ping
		in.LastPeer = &ping
	}
	if n.witness != nil {
		lease := n.witness.acquire(leaseRequest{ClusterID: simClusterID, Epoch: node.Epoch + 1, Holder: n.name})
		in.Lease = &lease
	} else {
		in.LeaseErr = "no witness is configured"
	}
	if n.fence {
		in.FenceRan = true
		in.FenceErr = c.fence(n)
	}
	if fail := FirstFailure(EvaluateAuto(in)); fail != nil {
		return
	}
	if in.Lease == nil || !in.Lease.Granted || in.Lease.Holder != n.name || in.Lease.Epoch != node.Epoch+1 {
		c.t.Fatalf("%s passed the gate without its own lease: %+v", n.name, in.Lease)
	}
	if expires := parseLeaseTime(in.Lease.ExpiresAt); !c.clock.Now().Before(expires) {
		c.t.Fatalf("%s passed the gate with an expired lease: %+v", n.name, in.Lease)
	}
	// Drive the same state machine the runtime does: standby becomes a ready
	// standby, then promoting. A leftover promoting role is finished directly.
	st := node.EffectiveState()
	if st == StateStandby {
		next, _, err := Next(st, EventReady)
		if err != nil || next != StateReadyStandby {
			c.t.Fatalf("ready %s: state %s, %v", n.name, next, err)
		}
		st = next
	}
	if st == StateReadyStandby {
		next, _, err := Next(st, EventPromote)
		if err != nil || next != StatePromoting {
			c.t.Fatalf("promote %s: state %s, %v", n.name, next, err)
		}
		st = next
	}
	if st != StatePromoting {
		c.t.Fatalf("%s tried to promote from %s", n.name, st)
	}
	role, err := BeginPromotion(n.dir, node, node.Epoch+1)
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := Activate(n.dir, role, role.Epoch); err != nil {
		c.t.Fatal(err)
	}
	n.guard.Record()
	n.promotions++
}

// fence models the operator's STONITH script: it reports the peer down and the
// peer really is down. A lying fence is the fault the epoch check exists for.
func (c *simCluster) fence(n *simNode) error {
	peer := c.peer(n)
	if !n.fence {
		return errors.New("the fence command is not configured")
	}
	peer.alive = false
	return nil
}

func (c *simCluster) checkAtMostOneActive() {
	c.t.Helper()
	active := 0
	for _, n := range c.nodes {
		node, err := Load(n.dir)
		if err != nil {
			c.t.Fatal(err)
		}
		if node.Active() && n.alive {
			active++
		}
	}
	if active > 1 {
		c.t.Fatalf("two serving actives at %s: %+v", c.clock.Now(), c.report())
	}
}

func (c *simCluster) report() []string {
	var out []string
	for _, n := range c.nodes {
		node, err := Load(n.dir)
		if err != nil {
			out = append(out, n.name+": "+err.Error())
			continue
		}
		out = append(out, fmt.Sprintf("%s: %s epoch=%d alive=%v promos=%d",
			n.name, node.EffectiveState(), node.Epoch, n.alive, n.promotions))
	}
	return out
}

// setRole rewrites one node's role file, keeping its identity.
func (c *simCluster) setRole(i int, role Role, epoch int64) {
	c.t.Helper()
	if err := Save(c.nodes[i].dir, &Node{NodeID: c.nodes[i].name, Role: role, Epoch: epoch}); err != nil {
		c.t.Fatal(err)
	}
}

func (c *simCluster) state(i int) State {
	c.t.Helper()
	node, err := Load(c.nodes[i].dir)
	if err != nil {
		c.t.Fatal(err)
	}
	return node.EffectiveState()
}

func TestSimPartitionMatrix(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*simCluster)
		ticks int
		want  int
	}{
		{
			name: "link down with both healthy",
			setup: func(c *simCluster) {
				c.tick()
				c.link = false
			},
			ticks: 6, want: 1,
		},
		{
			name: "active dies",
			setup: func(c *simCluster) {
				c.tick()
				c.nodes[0].alive = false
			},
			ticks: 6, want: 1,
		},
		{
			name: "standby dies",
			setup: func(c *simCluster) {
				c.tick()
				c.nodes[1].alive = false
			},
			ticks: 6, want: 1,
		},
		{
			name: "both die",
			setup: func(c *simCluster) {
				c.tick()
				c.nodes[0].alive, c.nodes[1].alive = false, false
			},
			ticks: 6, want: 0,
		},
		{
			name: "witness down",
			setup: func(c *simCluster) {
				c.tick()
				c.setRole(0, RoleStandby, 9)
				for _, n := range c.nodes {
					n.witness = nil
				}
				c.link = false
			},
			ticks: 6, want: 0,
		},
		{
			name: "witness split",
			setup: func(c *simCluster) {
				c.tick()
				c.link = false
			},
			ticks: 6, want: 1,
		},
		{
			name: "thirty seconds of clock skew",
			setup: func(c *simCluster) {
				c.tick()
				c.clock.Advance(30 * time.Second)
				c.nodes[1].mon.Now = func() time.Time { return c.clock.Now().Add(-30 * time.Second) }
				c.link = false
			},
			ticks: 6, want: 1,
		},
		{
			name: "standby disk full",
			setup: func(c *simCluster) {
				c.tick()
				c.nodes[0].alive = false
				c.nodes[1].diskFull = true
			},
			ticks: 6, want: 0,
		},
		{
			name: "fence fails",
			setup: func(c *simCluster) {
				c.tick()
				c.nodes[0].alive = false
				c.nodes[1].fence = false
			},
			ticks: 6, want: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			split := tc.name == "witness split"
			c := newSim(t, !split)
			tc.setup(c)
			for i := 0; i < tc.ticks; i++ {
				c.tick()
			}
			active := 0
			for _, n := range c.nodes {
				node, err := Load(n.dir)
				if err != nil {
					t.Fatal(err)
				}
				if node.Active() && n.alive {
					active++
				}
			}
			if active != tc.want {
				t.Fatalf("live actives = %d, want %d; %+v", active, tc.want, c.report())
			}
		})
	}
}

// TestSimHealsTwoActives is P6-05 in the simulator: a fault leaves two nodes
// believing they are active at different epochs, then the link returns. The lower
// epoch must stop serving and reconcile to the higher one.
func TestSimHealsTwoActives(t *testing.T) {
	c := newSim(t, false)
	c.setRole(0, RoleActive, 9)
	c.setRole(1, RoleActive, 10)
	c.tick()
	if got := c.state(0); got != StateSplitBrainRisk {
		t.Fatalf("lower epoch node = %s, want split-brain-risk", got)
	}
	c.tick()
	if got := c.state(0); got != StateStandby {
		t.Fatalf("lower epoch node after reconcile = %s, want standby", got)
	}
	if node, _ := Load(c.nodes[0].dir); node.Epoch != 10 {
		t.Fatalf("reconciled epoch = %d, want 10", node.Epoch)
	}
	if got := c.state(1); got != StateActive {
		t.Fatalf("higher epoch node = %s, want active", got)
	}
	c.checkAtMostOneActive()
}

// TestSimPromotionCrashLeavesNoActive kills the old active in the middle of the
// move: the epoch is on disk but the new node has not served, so nothing is
// active and a restart can finish from `promoting`.
func TestSimPromotionCrashLeavesNoActive(t *testing.T) {
	c := newSim(t, true)
	c.nodes[0].alive = false
	node, err := Load(c.nodes[1].dir)
	if err != nil {
		t.Fatal(err)
	}
	role, err := BeginPromotion(c.nodes[1].dir, node, 10)
	if err != nil {
		t.Fatal(err)
	}
	if role.EffectiveState() != StatePromoting || Serving(role.EffectiveState()) {
		t.Fatalf("mid-move role = %+v", role)
	}
	c.checkAtMostOneActive()
	if _, err := Activate(c.nodes[1].dir, role, 10); err != nil {
		t.Fatal(err)
	}
	if got := c.state(1); got != StateActive {
		t.Fatalf("after finishing the move = %s, want active", got)
	}
	c.checkAtMostOneActive()
}

// TestSimFlapParksThePair makes one node promote three times in the window; the
// fourth attempt must park it instead of promoting again.
func TestSimFlapParksThePair(t *testing.T) {
	c := newSim(t, true)
	c.tick() // one good heartbeat, so the gate has a baseline
	c.nodes[0].alive = false
	for i := 0; i < 3; i++ {
		c.tick() // three lost beats, then the promotion
	}
	if c.nodes[1].promotions != 1 {
		t.Fatalf("promotions after the first move = %d", c.nodes[1].promotions)
	}
	for i := 0; i < 2; i++ {
		if _, err := Demote(context.Background(), c.nodes[1].dir, Hooks{}); err != nil {
			t.Fatal(err)
		}
		c.tick()
	}
	if c.nodes[1].promotions != 3 {
		t.Fatalf("promotions in the window = %d, want 3", c.nodes[1].promotions)
	}
	if _, err := Demote(context.Background(), c.nodes[1].dir, Hooks{}); err != nil {
		t.Fatal(err)
	}
	c.tick()
	node, err := Load(c.nodes[1].dir)
	if err != nil {
		t.Fatal(err)
	}
	if node.EffectiveState() != StateParked || node.Reason == "" {
		t.Fatalf("after the fourth attempt = %+v", node)
	}
	if c.nodes[1].promotions != 3 {
		t.Fatalf("a parked node promoted again: %d moves", c.nodes[1].promotions)
	}
	for i := 0; i < 5; i++ {
		c.tick()
	}
	if got := c.state(1); got != StateParked {
		t.Fatalf("parked node became %s", got)
	}
}

// TestSimRandomPartitions runs the matrix with random failures. Every promotion
// is checked for a valid lease at promotion time, and no tick may ever leave two
// live nodes active.
func TestSimRandomPartitions(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 200; i++ {
		c := newSim(t, rng.Intn(2) == 0)
		for _, n := range c.nodes {
			n.fence = rng.Intn(2) == 0
		}
		c.tick() // baseline heartbeat before the random failures start
		for tick := 0; tick < 10; tick++ {
			c.link = rng.Intn(3) != 0
			for _, n := range c.nodes {
				if rng.Intn(12) == 0 {
					n.alive = false
				}
				n.fence = rng.Intn(2) == 0
				n.diskFull = rng.Intn(8) == 0
			}
			if rng.Intn(2) == 0 {
				c.clock.Advance(time.Duration(rng.Intn(12)) * time.Second)
			}
			c.tick()
		}
		c.checkAtMostOneActive()
	}
}
