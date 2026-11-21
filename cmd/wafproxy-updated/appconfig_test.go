package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/updates"
)

// newCheckout builds the shape configureApp validates: a git checkout of
// WAF-Proxy with an origin remote and the fixed update scripts.
func newCheckout(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	initCheckout(t, dir)

	for _, name := range []string{"wafproxy-self-update.sh", "wafproxy-self-update-check.sh"} {
		path := filepath.Join(dir, "deploy", name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func initCheckout(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{
		{"init", "-q", "-b", "main", dir},
		{"-C", dir, "remote", "add", "origin", "https://github.com/example/WAF-Proxy.git"},
	} {
		cmd := exec.Command("git", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
}

func TestConfigureAppRecordsCheckout(t *testing.T) {
	checkout := newCheckout(t)
	conf := filepath.Join(t.TempDir(), "etc", "self-update.conf")
	lib := filepath.Join(t.TempDir(), "lib")
	resp := configureAppAt(checkout, conf, lib)
	if !resp.OK {
		t.Fatalf("configureAppAt failed: %s", resp.Error)
	}
	values, err := updates.ReadSelfUpdateConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	if got := values["WAFPROXY_UPDATE_SOURCE_DIR"]; got != checkout {
		t.Fatalf("recorded source dir = %q, want %q", got, checkout)
	}
	if got := values["WAFPROXY_UPDATE_BRANCH"]; got != "main" {
		t.Fatalf("recorded branch = %q, want main", got)
	}
	if got := values["WAFPROXY_UPDATE_MODE"]; got != "native" {
		t.Fatalf("recorded mode = %q, want native", got)
	}
	for _, name := range []string{"self-update", "self-update-check"} {
		info, err := os.Stat(filepath.Join(lib, name))
		if err != nil {
			t.Fatalf("expected %s to be installed: %v", name, err)
		}
		if info.Mode().Perm() != 0o755 {
			t.Errorf("%s mode = %v, want 0755", name, info.Mode().Perm())
		}
	}
}

func TestConfigureAppRejectsBadDirectories(t *testing.T) {
	checkout := newCheckout(t)
	conf := filepath.Join(t.TempDir(), "self-update.conf")
	lib := t.TempDir()

	noGit := t.TempDir()
	noRemote := newCheckout(t)
	if out, err := exec.Command("git", "-C", noRemote, "remote", "remove", "origin").CombinedOutput(); err != nil {
		t.Fatalf("remove origin: %v\n%s", err, out)
	}
	noScript := newCheckout(t)
	if err := os.Remove(filepath.Join(noScript, "deploy", "wafproxy-self-update.sh")); err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"empty":      "",
		"relative":   "deploy",
		"missing":    filepath.Join(t.TempDir(), "absent"),
		"no .git":    noGit,
		"no origin":  noRemote,
		"no scripts": noScript,
	}
	for name, dir := range cases {
		if resp := configureAppAt(dir, conf, lib); resp.OK {
			t.Errorf("%s: configureAppAt accepted %q", name, dir)
		}
		if _, err := os.Stat(conf); err == nil {
			t.Fatalf("%s: configureAppAt wrote a conf file for a rejected directory", name)
		}
	}
	if resp := configureAppAt(checkout, conf, lib); !resp.OK {
		t.Fatalf("valid checkout rejected: %s", resp.Error)
	}
}

func TestConfigureAppKeepsDockerMode(t *testing.T) {
	checkout := newCheckout(t)
	conf := filepath.Join(t.TempDir(), "self-update.conf")
	if err := updates.WriteSelfUpdateConf(conf, map[string]string{
		"WAFPROXY_UPDATE_SOURCE_DIR": "/srv/old",
		"WAFPROXY_UPDATE_MODE":       "docker",
	}); err != nil {
		t.Fatal(err)
	}
	if resp := configureAppAt(checkout, conf, t.TempDir()); !resp.OK {
		t.Fatalf("configureAppAt failed: %s", resp.Error)
	}
	values, err := updates.ReadSelfUpdateConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	if got := values["WAFPROXY_UPDATE_MODE"]; got != "docker" {
		t.Fatalf("mode = %q, want docker preserved", got)
	}
	if !strings.Contains(values["WAFPROXY_UPDATE_SOURCE_DIR"], checkout) {
		t.Fatalf("source dir not updated: %q", values["WAFPROXY_UPDATE_SOURCE_DIR"])
	}
}
