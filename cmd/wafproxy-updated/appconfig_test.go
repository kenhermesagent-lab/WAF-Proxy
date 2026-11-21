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

// installScripts points the package's installed-script paths at a temp dir so
// tests never touch /usr/local.
func installScripts(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oldUpdate, oldCheck := updates.AppSelfUpdateScript, updates.AppCheckScript
	updates.AppSelfUpdateScript = filepath.Join(dir, "self-update")
	updates.AppCheckScript = filepath.Join(dir, "self-update-check")
	t.Cleanup(func() {
		updates.AppSelfUpdateScript = oldUpdate
		updates.AppCheckScript = oldCheck
	})
	return dir
}

func writeInstalledScripts(t *testing.T, dir string) {
	t.Helper()
	for _, name := range []string{"self-update", "self-update-check"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func TestConfigureAppRecordsCheckout(t *testing.T) {
	writeInstalledScripts(t, installScripts(t))
	checkout := newCheckout(t)
	conf := filepath.Join(t.TempDir(), "etc", "self-update.conf")
	resp := configureAppAt(checkout, conf)
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
	if strings.Contains(resp.Output, "missing") {
		t.Fatalf("unexpected missing-script note: %s", resp.Output)
	}
}

// Recording a directory must not copy anything out of the checkout into a
// root-run path: the admin supplies a path, never code.
func TestConfigureAppDoesNotInstallScripts(t *testing.T) {
	lib := installScripts(t)
	checkout := newCheckout(t)
	conf := filepath.Join(t.TempDir(), "self-update.conf")
	resp := configureAppAt(checkout, conf)
	if !resp.OK {
		t.Fatalf("configureAppAt failed: %s", resp.Error)
	}
	entries, err := os.ReadDir(lib)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("configureApp wrote into the installed script directory: %v", names)
	}
	if !strings.Contains(resp.Output, "install.sh") {
		t.Fatalf("output does not tell the admin to re-run install.sh: %s", resp.Output)
	}
}

func TestConfigureAppRejectsBadDirectories(t *testing.T) {
	installScripts(t)
	checkout := newCheckout(t)
	conf := filepath.Join(t.TempDir(), "self-update.conf")

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
		if resp := configureAppAt(dir, conf); resp.OK {
			t.Errorf("%s: configureAppAt accepted %q", name, dir)
		}
		if _, err := os.Stat(conf); err == nil {
			t.Fatalf("%s: configureAppAt wrote a conf file for a rejected directory", name)
		}
	}
	if resp := configureAppAt(checkout, conf); !resp.OK {
		t.Fatalf("valid checkout rejected: %s", resp.Error)
	}
}

func TestConfigureAppKeepsDockerMode(t *testing.T) {
	writeInstalledScripts(t, installScripts(t))
	checkout := newCheckout(t)
	conf := filepath.Join(t.TempDir(), "self-update.conf")
	if err := updates.WriteSelfUpdateConf(conf, map[string]string{
		"WAFPROXY_UPDATE_SOURCE_DIR": "/srv/old",
		"WAFPROXY_UPDATE_MODE":       "docker",
	}); err != nil {
		t.Fatal(err)
	}
	if resp := configureAppAt(checkout, conf); !resp.OK {
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

func TestConfigureAppReportsMissingInstalledScripts(t *testing.T) {
	installScripts(t) // directory exists but holds no scripts
	checkout := newCheckout(t)
	conf := filepath.Join(t.TempDir(), "self-update.conf")
	resp := configureAppAt(checkout, conf)
	if !resp.OK {
		t.Fatalf("recording the path should succeed even when scripts are missing: %s", resp.Error)
	}
	if !strings.Contains(resp.Output, "install.sh") || !strings.Contains(resp.Output, "self-update") {
		t.Fatalf("output does not point at install.sh: %s", resp.Output)
	}
}
