package main

import (
	"strings"
	"testing"

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
