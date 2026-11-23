package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/backup"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func TestSetupAndRecoverCLI(t *testing.T) {
	cfgDir := t.TempDir()
	t.Setenv("WAFPROXY_DATA_DIR", cfgDir)
	if err := setupCLI([]string{"--password", "a-long-enough-password"}); err != nil {
		t.Fatalf("first setup: %v", err)
	}
	if err := setupCLI([]string{"--password", "a-long-enough-password"}); err == nil {
		t.Fatal("setup ran twice on an initialized install")
	}

	if err := recoverCLI([]string{"--user", "admin", "--password", "another-long-password", "--reset-totp"}); err != nil {
		t.Fatalf("recover: %v", err)
	}
	st, err := store.Open(cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	user, err := st.UserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	if !auth.VerifyPassword(user.PasswordHash, "another-long-password") {
		t.Fatal("the new password does not verify")
	}
	if user.TOTPEnabled || user.TOTPSecret != "" {
		t.Fatal("TOTP was not cleared")
	}
}

func TestSetupRejectsShortPassword(t *testing.T) {
	t.Setenv("WAFPROXY_DATA_DIR", t.TempDir())
	err := setupCLI([]string{"--password", "short"})
	if err == nil || !strings.Contains(err.Error(), "12") {
		t.Fatalf("short password error = %v", err)
	}
}

func TestBackupCLIWritesEncryptedDocumentAndPrunes(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WAFPROXY_DATA_DIR", dir)
	if err := setupCLI([]string{"--password", "a-long-enough-password"}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "first.json.enc")
	if err := backupCLI([]string{"--out", out, "--passphrase", "a-sixteen-char-passphrase"}); err != nil {
		t.Fatalf("backup: %v", err)
	}
	sealed, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := backup.Decrypt("a-sixteen-char-passphrase", sealed)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(plain, &doc); err != nil || doc["version"] == nil {
		t.Fatalf("backup document = %v, %v", doc, err)
	}
	if err := backupCLI([]string{"--out", out, "--passphrase", "short"}); err == nil {
		t.Fatal("a short passphrase was accepted")
	}

	backupDir := filepath.Join(dir, "backups")
	if err := os.MkdirAll(backupDir, 0o750); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := 0; i < 3; i++ {
		path := filepath.Join(backupDir, "wafproxy-backup-0"+strconv.Itoa(i)+".json.enc")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		stamp := now.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := pruneBackups(backupDir, 2)
	if err != nil || removed != 1 {
		t.Fatalf("prune removed %d, err %v", removed, err)
	}
}
