package api

import (
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/plex"
)

func plexConfigWith(port int, listenIP string) plex.Config {
	return plex.Config{Port: port, ListenIP: listenIP, Upstream: "192.168.101.10:32400"}
}

func TestMergeEnvPreservesUnrelatedSettings(t *testing.T) {
	src := "# stack settings\nTZ=Europe/London\nWAFPROXY_LOG_LEVEL=info\nPLEX_PORT=32400\n"
	got := mergeEnv(src, map[string]string{
		"PLEX_ENABLED": "1",
		"PLEX_PORT":    "32401",
	})
	if !strings.Contains(got, "TZ=Europe/London") || !strings.Contains(got, "WAFPROXY_LOG_LEVEL=info") {
		t.Fatalf("unrelated settings were dropped:\n%s", got)
	}
	if !strings.Contains(got, "# stack settings") {
		t.Fatalf("comments were dropped:\n%s", got)
	}
	if !strings.Contains(got, "PLEX_PORT=32401") {
		t.Fatalf("existing key not updated:\n%s", got)
	}
	if !strings.Contains(got, "PLEX_ENABLED=1") {
		t.Fatalf("missing key not appended:\n%s", got)
	}
	if strings.Count(got, "PLEX_PORT=") != 1 || strings.Count(got, "PLEX_ENABLED=") != 1 {
		t.Fatalf("duplicate keys written:\n%s", got)
	}
}

func TestMergeEnvAddsTrailingNewline(t *testing.T) {
	got := mergeEnv("A=1", map[string]string{"B": "2"})
	if !strings.HasSuffix(got, "\n") {
		t.Fatalf("missing trailing newline: %q", got)
	}
	if !strings.Contains(got, "A=1") || !strings.Contains(got, "B=2") {
		t.Fatalf("unexpected result: %q", got)
	}
}

func TestPlexPortConflict(t *testing.T) {
	kv := map[string]string{"wan_ip": "192.168.191.2", "wan_port": "443", "lan_ip": "192.168.101.2", "gui_port": "8443"}
	cfg := plexConfigWith(443, "192.168.191.2")
	if msg := plexPortConflict(cfg, kv); msg == "" {
		t.Fatal("expected a conflict for the WAN port on the WAN address")
	}
	// A different address can reuse the port number.
	cfg = plexConfigWith(443, "192.168.101.2")
	if msg := plexPortConflict(cfg, kv); msg != "" {
		t.Fatalf("unexpected conflict: %s", msg)
	}
	cfg = plexConfigWith(32400, "192.168.191.2")
	if msg := plexPortConflict(cfg, kv); msg != "" {
		t.Fatalf("unexpected conflict: %s", msg)
	}
}
