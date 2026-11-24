package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/streaming"
)

// firewallShim puts a fake firewall-cmd on PATH and returns the file it logs
// every call to, so a save's real command sequence can be asserted.
func firewallShim(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the shim is a shell script")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	body := "#!/bin/sh\necho \"$*\" >> '" + log + "'\n" +
		"case \"$*\" in\n  *--state*) echo running ;;\n  *) echo success ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(dir, "firewall-cmd"), []byte(body), 0o755); err != nil {
		t.Fatalf("write shim: %v", err)
	}
	ufw := "#!/bin/sh\necho \"Status: inactive\"\n"
	if err := os.WriteFile(filepath.Join(dir, "ufw"), []byte(ufw), 0o755); err != nil {
		t.Fatalf("write shim: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

func shimCalls(t *testing.T, log string) string {
	t.Helper()
	raw, err := os.ReadFile(log)
	if err != nil {
		return ""
	}
	return string(raw)
}

// Enabling a forwarder binds it and opens the range; switching it off closes
// exactly that range again.
func TestStreamingSaveOpensAndClosesTheHostPort(t *testing.T) {
	log := firewallShim(t)
	srv, st, token, csrf := newObservabilityServer(t)
	m := streaming.New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.SetStreaming(m)
	t.Cleanup(m.Close)

	port := freeBothRange(t, 1)
	body := fmt.Sprintf(`{"enabled":true,"listen_ip":"127.0.0.1","protocol":"tcp","port":%d,`+
		`"port_count":1,"upstream":"10.0.0.10:%d","upstream_port":%d,"allow":"","max_conns":16,`+
		`"max_per_source":2,"idle_seconds":60,"max_datagram":1500,"list_ids":[]}`, port, port, port)
	rec := authed(t, srv, token, csrf, http.MethodPut, "/api/streaming/plex", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Applied  bool `json:"applied"`
		Firewall struct {
			Detail string `json:"detail"`
		} `json:"firewall"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Applied || !strings.Contains(resp.Firewall.Detail, "opened") {
		t.Fatalf("response = %+v, want the port opened", resp)
	}
	kv, err := st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if got := kv["stream_plex_firewall"]; got != strconv.Itoa(port)+"/tcp" {
		t.Fatalf("stream_plex_firewall = %q", got)
	}
	calls := shimCalls(t, log)
	if !strings.Contains(calls, "--permanent --add-port="+strconv.Itoa(port)+"/tcp") {
		t.Fatalf("no add-port call: %q", calls)
	}

	// Turning it off closes the same range and forgets it.
	off := strings.Replace(body, `"enabled":true`, `"enabled":false`, 1)
	rec = authed(t, srv, token, csrf, http.MethodPut, "/api/streaming/plex", off)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable PUT = %d: %s", rec.Code, rec.Body.String())
	}
	kv, err = st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if got := kv["stream_plex_firewall"]; got != "" {
		t.Fatalf("stream_plex_firewall after disabling = %q", got)
	}
	if calls := shimCalls(t, log); !strings.Contains(calls, "--remove-port="+strconv.Itoa(port)+"/tcp") {
		t.Fatalf("no remove-port call: %q", calls)
	}
}

// A listener that cannot bind must not leave a port open behind it.
func TestStreamingSaveLeavesTheFirewallAloneWhenTheListenerFails(t *testing.T) {
	log := firewallShim(t)
	srv, st, token, csrf := newObservabilityServer(t)
	m := streaming.New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.SetStreaming(m)
	t.Cleanup(m.Close)

	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = busy.Close() })
	port := busy.Addr().(*net.TCPAddr).Port

	body := fmt.Sprintf(`{"enabled":true,"listen_ip":"127.0.0.1","protocol":"tcp","port":%d,`+
		`"port_count":1,"upstream":"10.0.0.10:%d","upstream_port":%d,"allow":"","max_conns":16,`+
		`"max_per_source":2,"idle_seconds":60,"max_datagram":1500,"list_ids":[]}`, port, port, port)
	rec := authed(t, srv, token, csrf, http.MethodPut, "/api/streaming/plex", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Applied  bool   `json:"applied"`
		Error    string `json:"error"`
		Firewall struct {
			Detail string `json:"detail"`
		} `json:"firewall"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Applied || resp.Error == "" {
		t.Fatalf("response = %+v, want the bind failure reported", resp)
	}
	if !strings.Contains(resp.Firewall.Detail, "the listener did not start") {
		t.Fatalf("firewall = %+v, want the failure named", resp.Firewall)
	}
	if calls := shimCalls(t, log); strings.Contains(calls, "--add-port") {
		t.Fatalf("a port was opened for a listener that never started: %q", calls)
	}
	kv, err := st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if got := kv["stream_plex_firewall"]; got != "" {
		t.Fatalf("stream_plex_firewall = %q, want nothing recorded", got)
	}
}

// Moving a card to a port that cannot bind leaves the old range open unless it
// is closed, which would keep a dead forwarder reachable.
func TestStreamingRebindFailureClosesTheOldPort(t *testing.T) {
	log := firewallShim(t)
	srv, st, token, csrf := newObservabilityServer(t)
	m := streaming.New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.SetStreaming(m)
	t.Cleanup(m.Close)

	oldPort := freeBothRange(t, 1)
	put := func(port int) *httptest.ResponseRecorder {
		return authed(t, srv, token, csrf, http.MethodPut, "/api/streaming/plex",
			fmt.Sprintf(`{"enabled":true,"listen_ip":"127.0.0.1","protocol":"tcp","port":%d,`+
				`"port_count":1,"upstream":"10.0.0.10:%d","upstream_port":%d,"allow":"",`+
				`"max_conns":16,"max_per_source":2,"idle_seconds":60,"max_datagram":1500,"list_ids":[]}`,
				port, port, port))
	}
	if rec := put(oldPort); rec.Code != http.StatusOK {
		t.Fatalf("first PUT = %d: %s", rec.Code, rec.Body.String())
	}
	if calls := shimCalls(t, log); !strings.Contains(calls, "--add-port="+strconv.Itoa(oldPort)+"/tcp") {
		t.Fatalf("the first port was not opened: %q", calls)
	}

	// The new port is held by something else, so the rebind fails.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = busy.Close() })
	busyPort := busy.Addr().(*net.TCPAddr).Port

	rec := put(busyPort)
	if rec.Code != http.StatusOK {
		t.Fatalf("rebind PUT = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Applied  bool `json:"applied"`
		Firewall struct {
			Closed []string `json:"closed"`
			Detail string   `json:"detail"`
		} `json:"firewall"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	old := strconv.Itoa(oldPort) + "/tcp"
	if resp.Applied {
		t.Fatalf("the rebind reported success: %+v", resp)
	}
	if len(resp.Firewall.Closed) != 1 || resp.Firewall.Closed[0] != old {
		t.Fatalf("closed = %v, want %s", resp.Firewall.Closed, old)
	}
	calls := shimCalls(t, log)
	if !strings.Contains(calls, "--remove-port="+old) {
		t.Fatalf("the old port was not closed: %q", calls)
	}
	if strings.Contains(calls, "--add-port="+strconv.Itoa(busyPort)) {
		t.Fatalf("the failed port was opened: %q", calls)
	}
	kv, err := st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if got := kv["stream_plex_firewall"]; got != "" {
		t.Fatalf("stream_plex_firewall = %q, want the old range forgotten", got)
	}
}
