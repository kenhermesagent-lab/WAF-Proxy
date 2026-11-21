package updates

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Update button is only reported as supported while the recorded checkout
// and the installed updater scripts are actually present.
func TestAppUpdateSupportChecksRecordedCheckout(t *testing.T) {
	work := t.TempDir()
	socket := filepath.Join(work, "updates.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	scripts := t.TempDir()
	for _, name := range []string{"self-update", "self-update-check"} {
		if err := os.WriteFile(filepath.Join(scripts, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	oldUpdate, oldCheck := AppSelfUpdateScript, AppCheckScript
	AppSelfUpdateScript = filepath.Join(scripts, "self-update")
	AppCheckScript = filepath.Join(scripts, "self-update-check")
	defer func() {
		AppSelfUpdateScript, AppCheckScript = oldUpdate, oldCheck
	}()

	checkout := filepath.Join(work, "checkout")
	if err := os.MkdirAll(checkout, 0o755); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(work, "self-update.conf")
	if err := WriteSelfUpdateConf(conf, map[string]string{"WAFPROXY_UPDATE_SOURCE_DIR": checkout}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WAFPROXY_SELF_UPDATE_CONF", conf)

	m := &Manager{helperSocket: socket, appRepo: AppRepo}
	if snap := m.mergeApp(Snapshot{}, appInfo{}); !snap.AppUpdateSupported {
		t.Fatalf("supported = false with a recorded, existing checkout: %s", snap.AppUpdateReason)
	}
	if got := m.AppSourceDir(); got != checkout {
		t.Fatalf("AppSourceDir = %q, want %q", got, checkout)
	}

	if err := os.RemoveAll(checkout); err != nil {
		t.Fatal(err)
	}
	snap := m.mergeApp(Snapshot{}, appInfo{})
	if snap.AppUpdateSupported {
		t.Fatal("supported = true after the recorded checkout disappeared")
	}
	if !strings.Contains(snap.AppUpdateReason, "no longer exists") {
		t.Fatalf("reason = %q", snap.AppUpdateReason)
	}

	// A restored checkout with the scripts uninstalled is still unsupported:
	// the helper would have nothing fixed to run.
	if err := os.MkdirAll(checkout, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(scripts, "self-update")); err != nil {
		t.Fatal(err)
	}
	snap = m.mergeApp(Snapshot{}, appInfo{})
	if snap.AppUpdateSupported {
		t.Fatal("supported = true while an update script is missing")
	}
	if !strings.Contains(snap.AppUpdateReason, "install.sh") {
		t.Fatalf("reason = %q", snap.AppUpdateReason)
	}
}

func TestAppSourceDirEmptyWithoutConf(t *testing.T) {
	t.Setenv("WAFPROXY_SELF_UPDATE_CONF", filepath.Join(t.TempDir(), "absent.conf"))
	m := &Manager{}
	if got := m.AppSourceDir(); got != "" {
		t.Fatalf("AppSourceDir = %q, want empty", got)
	}
}

// A Docker install runs the console in a container, so the recorded checkout
// and the installed scripts live on the host and are invisible here. The helper
// reports them; the page must use that answer instead of stat()ing container
// paths that will never exist.
func TestAppUpdateSupportUsesHostStatusInContainer(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "updates.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	m := &Manager{
		helperSocket: socket,
		appRepo:      AppRepo,
		host:         hostInfo{container: true},
		appStatus: AppStatus{
			SourceDir:      "/srv/WAF-Proxy-Docker",
			Mode:           "docker",
			CheckoutExists: true,
		},
		appStatusOK: true,
	}
	snap := m.mergeApp(Snapshot{}, appInfo{})
	if !snap.AppUpdateSupported {
		t.Fatalf("supported = false with a host checkout: %s", snap.AppUpdateReason)
	}
	if snap.AppSourceDir != "/srv/WAF-Proxy-Docker" {
		t.Fatalf("AppSourceDir = %q", snap.AppSourceDir)
	}

	// Missing scripts are reported by the host, and the remedy names the Docker
	// installer rather than the native one.
	m.appStatus.MissingScripts = []string{"self-update"}
	snap = m.mergeApp(Snapshot{}, appInfo{})
	if snap.AppUpdateSupported {
		t.Fatal("supported = true while a host script is missing")
	}
	if !strings.Contains(snap.AppUpdateReason, "install-docker-updater.sh") {
		t.Fatalf("reason = %q", snap.AppUpdateReason)
	}
}
