package backup

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func TestValidateRejectsIncompleteDestinations(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"no transport", Config{Keep: 7}, "choose a backup destination"},
		{"relative dir", Config{Transport: "local", LocalDir: "backups", Keep: 7}, "absolute path"},
		{"sftp without host key", Config{Transport: "sftp", Host: "h", Port: 22, User: "u", Keep: 7}, "host key"},
		{"bad time", Config{Transport: "local", LocalDir: "/tmp/x", Time: "3am", Keep: 7}, "HH:MM"},
		{"bad keep", Config{Transport: "local", LocalDir: "/tmp/x", Keep: 0}, "keep"},
	}
	for _, tc := range cases {
		if got := tc.cfg.Validate(); got == "" || !strings.Contains(got, tc.want) {
			t.Errorf("%s: got %q, want a message containing %q", tc.name, got, tc.want)
		}
	}
}

func TestValidateAcceptsAFullConfig(t *testing.T) {
	c := Config{Transport: "sftp", Host: "backup.example.com", Port: 22, User: "u", HostKey: "abc", Keep: 7, Time: "03:00"}
	if msg := c.Validate(); msg != "" {
		t.Fatalf("unexpected rejection: %s", msg)
	}
}

func TestWriteLocalPrunesOldFiles(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "wafproxy-backup-20240101-000000.json")
	if err := os.WriteFile(old, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeLocal(dir, "wafproxy-backup-20240102-000000.json", []byte("{}"), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("old backup was not pruned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "wafproxy-backup-20240102-000000.json")); err != nil {
		t.Fatalf("new backup missing: %v", err)
	}
}

// A local destination saved without a port must read back as SFTP's default,
// or switching the transport later fails validation with a port of zero.
func TestConfigDefaultsTheRemotePort(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	box, err := crypto.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	m := New(st, box, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err := m.Save(Config{Transport: "local", LocalDir: "/tmp/backups", Keep: 3, Time: "03:00"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := m.Config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 22 {
		t.Fatalf("port = %d, want 22", cfg.Port)
	}
}

func TestNextRunDailyRollsForward(t *testing.T) {
	local := time.FixedZone("UTC+0", 0)
	now := time.Date(2026, 3, 2, 4, 0, 0, 0, local)
	next, ok := nextRun(Config{Enabled: true, Schedule: "daily", Time: "03:00"}, now)
	if !ok {
		t.Fatal("expected a scheduled run")
	}
	if want := time.Date(2026, 3, 3, 3, 0, 0, 0, local); !next.Equal(want) {
		t.Fatalf("next run = %s, want %s", next, want)
	}
	if _, ok := nextRun(Config{Enabled: false, Schedule: "daily", Time: "03:00"}, now); ok {
		t.Fatal("a disabled schedule must not report a next run")
	}
}

func TestParseFingerprintRejectsAMismatch(t *testing.T) {
	cb, err := parseFingerprint("SHA256:wanted")
	if err != nil {
		t.Fatal(err)
	}
	if err := cb("host", nil, testKey{}); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected a mismatch, got %v", err)
	}
}

type testKey struct{}

func (testKey) Type() string                        { return "ssh-ed25519" }
func (testKey) Marshal() []byte                     { return nil }
func (testKey) Verify([]byte, *ssh.Signature) error { return nil }
