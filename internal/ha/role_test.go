package ha

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRoleRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := &Node{NodeID: "node-a", Role: RoleActive, Epoch: 3, Peer: "10.0.0.11:9443"}
	if err := Save(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.NodeID != want.NodeID || got.Role != want.Role || got.Epoch != want.Epoch || got.Peer != want.Peer {
		t.Fatalf("loaded %+v, want %+v", got, want)
	}
	if got.UpdatedAt == "" {
		t.Fatal("Save did not stamp updated_at")
	}
	info, err := os.Stat(filepath.Join(RoleDir(dir), "node.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestRoleFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty", ""},
		{"truncated", `{"node_id":"a","role":"active"`},
		{"unknown role", `{"node_id":"a","role":"master","epoch":1}`},
		{"missing node id", `{"role":"active","epoch":1}`},
		{"negative epoch", `{"node_id":"a","role":"active","epoch":-1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(RoleDir(dir), 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(RoleDir(dir), "node.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			n, err := Load(dir)
			if err == nil {
				t.Fatalf("Load(%q) returned no error", tc.body)
			}
			if n.Role != RoleStandby || n.Active() {
				t.Fatalf("Load(%q) = %+v, want standby", tc.body, n)
			}
		})
	}
}

func TestRoleWrongModeAndSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := Save(dir, &Node{NodeID: "a", Role: RoleActive, Epoch: 1}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(RoleDir(dir), "node.json")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if n, err := Load(dir); err == nil || n.Active() {
		t.Fatalf("Load with mode 0644 = %+v, %v; want standby and an error", n, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{"node_id":"a","role":"active","epoch":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if n, err := Load(dir); err == nil || n.Active() {
		t.Fatalf("Load through symlink = %+v, %v; want standby and an error", n, err)
	}
}

func TestRoleMissingFileIsStandby(t *testing.T) {
	n, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("missing file should not be an error: %v", err)
	}
	if n.Role != RoleStandby || n.Active() {
		t.Fatalf("missing file = %+v, want standby", n)
	}
}

func TestRoleRejectsInvalidSave(t *testing.T) {
	dir := t.TempDir()
	if err := Save(dir, &Node{NodeID: "a", Role: "master"}); err == nil {
		t.Fatal("Save accepted an unknown role")
	}
	if err := Save(dir, &Node{Role: RoleActive, Epoch: 1}); err == nil {
		t.Fatal("Save accepted an empty node id")
	}
	if err := Save(dir, &Node{NodeID: "a", Role: RoleActive, Epoch: -1}); err == nil {
		t.Fatal("Save accepted a negative epoch")
	}
}
