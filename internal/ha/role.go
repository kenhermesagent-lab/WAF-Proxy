// Package ha holds the node role, the pair state and the replication plan.
package ha

import (
	"encoding/json"
	"errors"
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
	NodeID    string `json:"node_id"`
	Role      Role   `json:"role"`
	Epoch     int64  `json:"epoch"`
	Peer      string `json:"peer,omitempty"`
	UpdatedAt string `json:"updated_at"`
}

// Active reports whether the node may serve traffic and run background loops.
// Standalone is the HA-off state and stays active, so a single node behaves
// exactly as it did before HA existed.
func (n *Node) Active() bool {
	return n.Role == RoleActive || n.Role == RoleStandalone
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
	return &n, nil
}

// Save writes the role file atomically: a crash leaves either the old record
// or the new one, never a truncated file that would demote a healthy node.
func Save(dataDir string, n *Node) error {
	if !validRole(n.Role) {
		return errors.New("ha: invalid role")
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
