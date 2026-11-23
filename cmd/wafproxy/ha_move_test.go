package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ha"
)

// fakeControl answers one command per accepted connection with the replies the
// test provides, so the CLI path is exercised without a live node.
func fakeControl(t *testing.T, replies []ha.ControlReply) (string, *[]ha.ControlRequest) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "ha.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var seen []ha.ControlRequest
	go func() {
		for _, reply := range replies {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req ha.ControlRequest
			_ = json.NewDecoder(conn).Decode(&req)
			mu.Lock()
			seen = append(seen, req)
			mu.Unlock()
			_ = json.NewEncoder(conn).Encode(reply)
			_ = conn.Close()
		}
	}()
	t.Setenv("WAFPROXY_HA_CONTROL_SOCKET", sock)
	t.Setenv("WAFPROXY_DATA_DIR", dir)
	return sock, &seen
}

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	runErr := fn()
	_ = w.Close()
	os.Stdout = old
	raw, _ := io.ReadAll(r)
	return string(raw), runErr
}

func TestHAMoveCLIDryRunJSON(t *testing.T) {
	_, seen := fakeControl(t, []ha.ControlReply{{
		OK: true,
		Result: &ha.Result{DryRun: true, Epoch: 4, Checks: []ha.Check{
			{Name: "peer-reachable", OK: true, Detail: "the peer answered on the HA link"},
			{Name: "disk", OK: false, Detail: "1.0% free", Fix: "free space on the data volume"},
		}},
	}})
	out, err := captureStdout(t, func() error {
		return haMoveCLI("failover", []string{"--dry-run", "--json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"dry_run": true`) || !strings.Contains(out, `"name": "disk"`) {
		t.Fatalf("dry-run output = %s", out)
	}
	if len(*seen) != 1 || (*seen)[0].Command != "failover" || !(*seen)[0].DryRun {
		t.Fatalf("request = %+v", *seen)
	}
}

func TestHAMoveCLIRefusalExitsNonZero(t *testing.T) {
	fakeControl(t, []ha.ControlReply{{
		OK:      false,
		Error:   "ha: preflight failed at disk: 1.0% free",
		Blocked: &ha.Check{Name: "disk", Detail: "1.0% free", Fix: "free space on the data volume"},
		Result:  &ha.Result{DryRun: false, Steps: []ha.Step{{Name: "quiesce-peer", OK: false, Detail: "refused"}}},
	}})
	out, err := captureStdout(t, func() error {
		return haMoveCLI("failback", []string{"--force"})
	})
	if err == nil || !strings.Contains(err.Error(), "preflight failed") {
		t.Fatalf("refusal error = %v", err)
	}
	if !strings.Contains(out, "forced past") && !strings.Contains(out, "quiesce-peer") {
		t.Fatalf("refusal output = %s", out)
	}
}

func TestWitnessCLIRequiresAToken(t *testing.T) {
	t.Setenv("WAFPROXY_HA_WITNESS_TOKEN", "")
	if err := haWitnessCLI([]string{"--listen", "127.0.0.1:0"}); err == nil {
		t.Fatal("the witness started without a token")
	}
}

func TestHANotifyPassesTheRole(t *testing.T) {
	_, seen := fakeControl(t, []ha.ControlReply{{OK: true}})
	if err := haNotifyCLI([]string{"backup"}); err != nil {
		t.Fatal(err)
	}
	if len(*seen) != 1 || (*seen)[0].Command != "notify" || (*seen)[0].Role == "" {
		t.Fatalf("request = %+v", *seen)
	}
}
