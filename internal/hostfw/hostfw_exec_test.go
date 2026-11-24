package hostfw

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// shimDir puts fake firewall-cmd and ufw binaries on PATH and returns the log
// they append to, so the real Opener execs the real arguments without a host
// firewall. Each script answers the way its tool does and records the call.
func shimDir(t *testing.T, firewalld, ufw string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the shims are shell scripts")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	script := func(name, body string) {
		path := filepath.Join(dir, name)
		content := "#!/bin/sh\necho \"" + name + " $*\" >> '" + log + "'\n" + body + "\n"
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	script("firewall-cmd", firewalld)
	script("ufw", ufw)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

func calls(t *testing.T, log string) []string {
	t.Helper()
	raw, err := os.ReadFile(log)
	if err != nil {
		return nil
	}
	lines := []string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// The firewalld sequence is what the docs promise: every range is added with
// --permanent, the reload happens once, and a moved range is removed before the
// new one is reloaded in.
func TestRealFirewalldCommandSequence(t *testing.T) {
	log := shimDir(t, `case "$*" in
  *--state*) echo running ;;
  *) echo success ;;
esac`, `echo "Status: inactive"`)

	rep := New().Sync(context.Background(), ForConfig(2456, 3, "udp"), nil)
	if rep.Error != "" {
		t.Fatalf("sync: %+v", rep)
	}
	got := calls(t, log)
	want := []string{
		"firewall-cmd --state",
		"firewall-cmd --permanent --add-port=2456-2458/udp",
		"firewall-cmd --reload",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %v, want %v", got, want)
	}

	// A range that moved closes the old rule in the same reload.
	os.Remove(log)
	rep = New().Sync(context.Background(), ForConfig(8096, 1, "tcp"), []string{"2456-2458/udp"})
	if rep.Error != "" || len(rep.Opened) != 1 || len(rep.Closed) != 1 {
		t.Fatalf("move: %+v", rep)
	}
	got = calls(t, log)
	want = []string{
		"firewall-cmd --state",
		"firewall-cmd --permanent --add-port=8096/tcp",
		"firewall-cmd --permanent --remove-port=2456-2458/udp",
		"firewall-cmd --reload",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("move calls = %v, want %v", got, want)
	}
}

// ufw takes a colon range and a bare service spec, which is the one argument
// form the fake runner cannot prove.
func TestRealUFWCommandSequence(t *testing.T) {
	log := shimDir(t, `echo "FirewallD is not running"`, `case "$*" in
  status) echo "Status: active" ;;
  *) echo "Rule added" ;;
esac`)

	rep := New().Sync(context.Background(), ForConfig(2456, 3, "udp"), nil)
	if rep.Error != "" {
		t.Fatalf("sync: %+v", rep)
	}
	got := calls(t, log)
	want := []string{"firewall-cmd --state", "ufw status", "ufw allow 2456:2458/udp"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %v, want %v", got, want)
	}

	os.Remove(log)
	rep = New().Sync(context.Background(), nil, []string{"2456-2458/udp"})
	if rep.Error != "" || len(rep.Closed) != 1 {
		t.Fatalf("disable: %+v", rep)
	}
	got = calls(t, log)
	want = []string{"firewall-cmd --state", "ufw status", "ufw delete allow 2456:2458/udp"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("disable calls = %v, want %v", got, want)
	}
}

// A failing tool is reported with its own message and leaves the rest alone.
func TestRealCommandFailureIsReported(t *testing.T) {
	shimDir(t, `case "$*" in
  *--state*) echo running ;;
  *--remove-port*) echo "NOT_ENABLED: '2456-2458/udp' not in 'public'" >&2; exit 1 ;;
  *) echo success ;;
esac`, `echo "Status: inactive"`)

	rep := New().Sync(context.Background(), nil, []string{"2456-2458/udp"})
	if rep.Error == "" || len(rep.Closed) != 0 {
		t.Fatalf("report = %+v", rep)
	}
	if !strings.Contains(rep.Error, "NOT_ENABLED") {
		t.Fatalf("the tool's message was lost: %q", rep.Error)
	}
}
