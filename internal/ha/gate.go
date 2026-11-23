package ha

import "sync/atomic"

// Gate decides whether background work may run on this node. A standby keeps
// its database current but must not renew certificates, fetch feeds, reconcile
// nftables or send alerts: those are the active's job, and running them twice
// is how a pair corrupts itself.
type Gate struct {
	active atomic.Bool
}

// NewGate returns a gate that is open when active is true. With HA off the
// caller passes true, so a single node behaves exactly as before.
func NewGate(active bool) *Gate {
	g := &Gate{}
	g.SetActive(active)
	return g
}

// SetActive opens or closes the gate. P1 calls it on every role transition.
func (g *Gate) SetActive(active bool) { g.active.Store(active) }

// Active reports whether this node may run active-only work.
func (g *Gate) Active() bool { return g.active.Load() }

// Go starts fn in a goroutine only when the gate is open.
func (g *Gate) Go(fn func()) bool {
	if !g.Active() {
		return false
	}
	go fn()
	return true
}

// Do runs fn inline only when the gate is open.
func (g *Gate) Do(fn func()) bool {
	if !g.Active() {
		return false
	}
	fn()
	return true
}
