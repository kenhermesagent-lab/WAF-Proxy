package ha

import (
	"fmt"
	"sync"
	"time"
)

// DefaultMaxMovesPerHour is where a pair stops moving on its own. Three moves in
// an hour is already suspicious; the fourth is a peer that keeps failing, and
// another promotion only makes the outage longer.
const DefaultMaxMovesPerHour = 3

// FlapGuard parks automatic moves when the pair moves too often. It counts
// successful promotions, not attempts: a move that was refused changed nothing.
type FlapGuard struct {
	Max    int
	Window time.Duration
	Now    func() time.Time

	mu    sync.Mutex
	moves []time.Time
}

// NewFlapGuard builds a guard with the default window.
func NewFlapGuard(max int) *FlapGuard {
	if max <= 0 {
		max = DefaultMaxMovesPerHour
	}
	return &FlapGuard{Max: max, Window: time.Hour, Now: time.Now}
}

// Check prunes the window and reports whether one more move is allowed.
func (g *FlapGuard) Check() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	cutoff := g.Now().Add(-g.Window)
	kept := g.moves[:0]
	for _, t := range g.moves {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	g.moves = kept
	if len(g.moves) >= g.Max {
		return fmt.Errorf("ha: %d automatic moves in %s; the pair is parked for an operator", len(g.moves), g.Window)
	}
	return nil
}

// Record notes a completed promotion.
func (g *FlapGuard) Record() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.moves = append(g.moves, g.Now())
}
