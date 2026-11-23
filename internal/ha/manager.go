package ha

import (
	"context"
	"errors"
	"sync"
	"time"
)

// MoveOptions are the operator's choices for one move.
type MoveOptions struct {
	DryRun bool `json:"dry_run"`
	Force  bool `json:"force"`
}

// Status is the control socket's view of the node and any move in progress.
type Status struct {
	Role      Role    `json:"role"`
	State     State   `json:"state"`
	Epoch     int64   `json:"epoch"`
	Paired    bool    `json:"paired"`
	Running   bool    `json:"running"`
	Serving   bool    `json:"serving"`
	StartedAt string  `json:"started_at,omitempty"`
	Last      *Result `json:"last,omitempty"`
	LastError string  `json:"last_error,omitempty"`
}

// Manager serialises moves, exposes their state, and gives an operator a way to
// abort one before it becomes irreversible.
type Manager struct {
	dataDir string
	hooks   Hooks

	mu        sync.Mutex
	running   bool
	serving   bool
	cancel    context.CancelFunc
	startedAt time.Time
	last      Result
	lastErr   string
}

// NewManager builds the move coordinator for one node.
func NewManager(dataDir string, hooks Hooks) *Manager {
	return &Manager{dataDir: dataDir, hooks: hooks}
}

// Failover promotes this standby, or explains why it refused.
func (m *Manager) Failover(ctx context.Context, opts MoveOptions) (Result, error) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return Result{}, errors.New("ha: a move is already in progress")
	}
	runCtx, cancel := context.WithCancel(ctx)
	m.running = true
	m.serving = false
	m.cancel = cancel
	m.startedAt = time.Now()
	m.lastErr = ""
	m.mu.Unlock()

	// Once the data plane serves, an abort must not cancel the role write.
	hooks := m.hooks
	if hooks.Serve != nil {
		serve := hooks.Serve
		hooks.Serve = func(c context.Context) error {
			if err := serve(c); err != nil {
				return err
			}
			m.mu.Lock()
			m.serving = true
			m.mu.Unlock()
			return nil
		}
	}

	res, err := Promote(runCtx, m.dataDir, hooks, opts.Force, opts.DryRun)
	cancel()

	m.mu.Lock()
	m.running = false
	m.cancel = nil
	m.last = res
	if err != nil {
		m.lastErr = err.Error()
	}
	node, loadErr := Load(m.dataDir)
	if loadErr == nil {
		m.serving = node.Active()
	}
	m.mu.Unlock()
	return res, err
}

// Failback drains this node and returns it to standby. Promoting the other node
// is a separate move, run on that node.
func (m *Manager) Failback(ctx context.Context, opts MoveOptions) (Result, error) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return Result{}, errors.New("ha: a move is already in progress")
	}
	runCtx, cancel := context.WithCancel(ctx)
	m.running = true
	m.cancel = cancel
	m.startedAt = time.Now()
	m.lastErr = ""
	m.mu.Unlock()

	res, err := Demote(runCtx, m.dataDir, m.hooks)
	cancel()

	m.mu.Lock()
	m.running = false
	m.serving = false
	m.cancel = nil
	m.last = res
	if err != nil {
		m.lastErr = err.Error()
	}
	m.mu.Unlock()
	return res, err
}

// Abort cancels a move that has not reached the data plane. After Serve, the
// only safe reversal is a failback, so it says so instead of pretending.
func (m *Manager) Abort() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running {
		return errors.New("ha: no move is in progress")
	}
	if m.serving {
		return errors.New("ha: the move has already reached the data plane; run `wafproxy ha failback` instead")
	}
	if m.cancel != nil {
		m.cancel()
	}
	return nil
}

// Status reads the role file fresh, so it cannot disagree with the data plane.
func (m *Manager) Status() Status {
	node, _ := Load(m.dataDir) // a damaged file already loads as standby
	pair, _ := LoadPair(m.dataDir)
	st := Status{
		Role: node.Role, State: node.EffectiveState(), Epoch: node.Epoch,
		Paired: pair != nil, Serving: node.Active(),
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st.Running = m.running
	if m.serving {
		st.Serving = true
	}
	if m.running {
		st.StartedAt = m.startedAt.UTC().Format(time.RFC3339)
	}
	if m.last.Epoch != 0 || len(m.last.Steps) > 0 || len(m.last.Checks) > 0 {
		last := m.last
		st.Last = &last
	}
	st.LastError = m.lastErr
	return st
}
