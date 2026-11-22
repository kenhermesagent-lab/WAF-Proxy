package api

import (
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/streaming"
)

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

func TestStreamingPortConflict(t *testing.T) {
	srv := &Server{}
	plex, _ := streaming.Lookup("plex")
	jellyfin, _ := streaming.Lookup("jellyfin")
	kv := map[string]string{
		"wan_ip": "192.168.191.2", "wan_port": "443",
		"lan_ip": "10.0.0.2", "gui_port": "8443",
		"stream_jellyfin_enabled": "1", "stream_jellyfin_port": "8096", "stream_jellyfin_listen_ip": "192.168.191.2",
	}

	cfg := streaming.Config{Port: 443, ListenIP: "192.168.191.2", Upstream: "10.0.0.10:32400"}
	if msg := srv.streamingPortConflict(plex, cfg, kv); msg == "" {
		t.Fatal("expected a conflict for the WAN port on the WAN address")
	}
	// A different address can reuse the port number.
	cfg.ListenIP = "10.0.0.2"
	if msg := srv.streamingPortConflict(plex, cfg, kv); msg != "" {
		t.Fatalf("unexpected conflict: %s", msg)
	}
	// Two streaming services may not share an address and port.
	cfg = streaming.Config{Port: 8096, ListenIP: "192.168.191.2", Upstream: "10.0.0.10:32400"}
	if msg := srv.streamingPortConflict(plex, cfg, kv); !strings.Contains(msg, "Jellyfin") {
		t.Fatalf("conflict = %q, want it to name Jellyfin", msg)
	}
	// Jellyfin checking against itself is not a conflict.
	if msg := srv.streamingPortConflict(jellyfin, cfg, kv); msg != "" {
		t.Fatalf("unexpected self conflict: %s", msg)
	}
	cfg = streaming.Config{Port: 32400, ListenIP: "192.168.191.2", Upstream: "10.0.0.10:32400"}
	if msg := srv.streamingPortConflict(plex, cfg, kv); msg != "" {
		t.Fatalf("unexpected conflict: %s", msg)
	}
}
