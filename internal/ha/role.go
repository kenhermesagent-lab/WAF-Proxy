// Package ha holds the node role, the pair state and the replication plan.
package ha

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Role is what this node is allowed to do. The zero value is not active, so a
// missing or damaged role file can never promote a node.
type Role string

const (
	RoleStandalone Role = "standalone"
	RoleActive     Role = "active"
	RoleStandby    Role = "standby"
)

// Node is the local, un-replicated role record. It lives on disk rather than in
// SQLite so a database restore cannot silently change which node serves.
type Node struct {
	NodeID string `json:"node_id"`
	Role   Role   `json:"role"`
	// State is the finer-grained place in a move. It is optional so a role file
	// written before P5 still loads; an empty state is derived from the role.
	State State `json:"state,omitempty"`
	// Reason explains a parked or split-brain state, so `ha status` says why.
	Reason    string `json:"reason,omitempty"`
	Epoch     int64  `json:"epoch"`
	Peer      string `json:"peer,omitempty"`
	UpdatedAt string `json:"updated_at"`
}

// Active reports whether the node may serve traffic and run background loops.
// Standalone is the HA-off state and stays active, so a single node behaves
// exactly as it did before HA existed. A node that persisted `promoting` is
// still a standby by role and does not serve.
func (n *Node) Active() bool {
	return n.Role == RoleActive || n.Role == RoleStandalone
}

// EffectiveState is the state the console and `ha status` show. A role file
// from before P5 has no state, so it is derived from the role.
func (n *Node) EffectiveState() State {
	if n.State != "" {
		return n.State
	}
	switch n.Role {
	case RoleActive:
		return StateActive
	case RoleStandalone:
		return StateStandalone
	default:
		return StateStandby
	}
}

// RoleDir returns the directory holding the role file for a data directory.
func RoleDir(dataDir string) string { return filepath.Join(dataDir, "ha") }

// Load reads the role file. A missing, unreadable, wrongly permissioned or
// unparsable file yields a standby node, never an active one; readiness is
// decided by the caller from the error.
func Load(dataDir string) (*Node, error) {
	path := filepath.Join(RoleDir(dataDir), "node.json")
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Node{Role: RoleStandby}, nil
		}
		return &Node{Role: RoleStandby}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return &Node{Role: RoleStandby}, errors.New("ha: role file must not be a symlink")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return &Node{Role: RoleStandby}, errors.New("ha: role file must be a regular file with mode 0600")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return &Node{Role: RoleStandby}, err
	}
	var n Node
	if err := json.Unmarshal(raw, &n); err != nil {
		return &Node{Role: RoleStandby}, err
	}
	if !validRole(n.Role) || n.NodeID == "" || n.Epoch < 0 {
		return &Node{Role: RoleStandby}, errors.New("ha: invalid role file")
	}
	if n.State != "" && !validState(n.State) {
		return &Node{Role: RoleStandby}, errors.New("ha: invalid role file state")
	}
	return &n, nil
}

// Save writes the role file atomically: a crash leaves either the old record
// or the new one, never a truncated file that would demote a healthy node.
func Save(dataDir string, n *Node) error {
	if !validRole(n.Role) {
		return errors.New("ha: invalid role")
	}
	if n.State != "" && !validState(n.State) {
		return errors.New("ha: invalid state")
	}
	if n.NodeID == "" || n.Epoch < 0 {
		return errors.New("ha: node id and a non-negative epoch are required")
	}
	n.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.Marshal(n)
	if err != nil {
		return err
	}
	dir := RoleDir(dataDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "node-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, filepath.Join(dir, "node.json")); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func validRole(r Role) bool {
	return r == RoleStandalone || r == RoleActive || r == RoleStandby
}

func validState(s State) bool {
	switch s {
	case StateStandalone, StateStandby, StateReadyStandby, StatePromoting,
		StateActive, StateDraining, StateDemoting, StateFenced, StateSplitBrainRisk, StateParked:
		return true
	}
	return false
}

// BeginPromotion persists the next epoch before any listener may accept. The
// role stays standby, so a crash at this point restarts as a promoting standby
// rather than an active node with the old epoch. Save fsyncs the file and its
// directory before returning.
func BeginPromotion(dataDir string, n *Node, epoch int64) (*Node, error) {
	if n.Role != RoleStandby && n.Role != RoleStandalone {
		return nil, fmt.Errorf("ha: cannot promote a %s node", n.Role)
	}
	if epoch <= n.Epoch {
		return nil, fmt.Errorf("ha: promotion epoch %d must be above %d", epoch, n.Epoch)
	}
	out := *n
	out.State = StatePromoting
	out.Epoch = epoch
	if err := Save(dataDir, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Activate writes the new role and epoch after the promotion sequence has done
// its work. Callers serve only after this returns.
func Activate(dataDir string, n *Node, epoch int64) (*Node, error) {
	out := *n
	out.Role = RoleActive
	out.State = StateActive
	out.Reason = ""
	out.Epoch = epoch
	if err := Save(dataDir, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ReturnToStandby records that this node no longer serves. It keeps the epoch,
// because a later promotion must still move past it.
func ReturnToStandby(dataDir string, n *Node) (*Node, error) {
	return EnterState(dataDir, n, StateStandby)
}

// MakeStandalone turns a leftover HA standby into a single node when HA is off.
// The epoch is kept, so a later promotion still starts above it.
func MakeStandalone(dataDir string, n *Node) (*Node, error) {
	if n.Active() {
		return n, nil
	}
	out := *n
	out.Role = RoleStandalone
	out.State = StateStandalone
	out.Reason = ""
	if err := Save(dataDir, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// EnterState records that a standby is in a named state, keeping its epoch. It
// is how split-brain-risk and parked survive a restart.
func EnterState(dataDir string, n *Node, state State) (*Node, error) {
	if !validState(state) {
		return nil, errors.New("ha: invalid state")
	}
	out := *n
	out.Role = RoleStandby
	out.State = state
	if state == StateStandby {
		out.Reason = ""
	}
	if err := Save(dataDir, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Reconcile clears split-brain-risk once the peer answers again: this node stays
// a standby and adopts the peer's epoch, so its next move starts above it.
func Reconcile(dataDir string, n *Node, peerEpoch int64) (*Node, error) {
	if n.State != StateSplitBrainRisk {
		return nil, fmt.Errorf("ha: reconcile needs a split-brain-risk node, not %s", n.EffectiveState())
	}
	out := *n
	out.Role = RoleStandby
	out.State = StateStandby
	out.Reason = ""
	if peerEpoch > out.Epoch {
		out.Epoch = peerEpoch
	}
	if err := Save(dataDir, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Park stops automatic moves until an operator moves by hand. The reason is
// kept so a restart cannot quietly resume a flapping pair.
func Park(dataDir string, n *Node, reason string) (*Node, error) {
	if n.Active() {
		return nil, errors.New("ha: park a standby, not an active node")
	}
	if len(reason) > 200 {
		reason = reason[:200]
	}
	out := *n
	out.Role = RoleStandby
	out.State = StateParked
	out.Reason = reason
	if err := Save(dataDir, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
