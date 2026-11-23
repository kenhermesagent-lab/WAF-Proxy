package api

import (
	"reflect"
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

// TCP and UDP are separate sockets, so a game that needs both may share a
// number with another service, but not the same protocol.
func TestStreamingPortConflictProtocols(t *testing.T) {
	srv := &Server{}
	plex, _ := streaming.Lookup("plex")
	kv := map[string]string{
		"wan_ip": "192.168.191.2", "wan_port": "443",
		"lan_ip": "10.0.0.2", "gui_port": "8443",
		"stream_custom_enabled": "1", "stream_custom_port": "30120",
		"stream_custom_protocol": "tcp", "stream_custom_listen_ip": "192.168.191.2",
	}

	cfg := streaming.Config{Port: 30120, PortCount: 1, Protocol: "udp", ListenIP: "192.168.191.2"}
	if msg := srv.streamingPortConflict(plex, cfg, kv); msg != "" {
		t.Fatalf("udp beside a tcp service conflicted: %s", msg)
	}
	cfg.Protocol = "tcp"
	if msg := srv.streamingPortConflict(plex, cfg, kv); !strings.Contains(msg, "Custom") {
		t.Fatalf("conflict = %q, want it to name the Custom service", msg)
	}

	// A range overlaps when any port in it is taken.
	cfg = streaming.Config{Port: 30119, PortCount: 2, Protocol: "tcp", ListenIP: "192.168.191.2"}
	if msg := srv.streamingPortConflict(plex, cfg, kv); msg == "" {
		t.Fatal("a range covering a taken port was allowed")
	}

	// The WAN listener is TCP, so a UDP service may reuse 443.
	cfg = streaming.Config{Port: 443, PortCount: 1, Protocol: "udp", ListenIP: "192.168.191.2"}
	if msg := srv.streamingPortConflict(plex, cfg, kv); msg != "" {
		t.Fatalf("udp on the WAN port conflicted: %s", msg)
	}
	cfg.Protocol = "both"
	if msg := srv.streamingPortConflict(plex, cfg, kv); !strings.Contains(msg, "WAN") {
		t.Fatalf("conflict = %q, want the WAN listener", msg)
	}
}

// Every key a save writes must load back into the configuration it came from.
func TestStreamingSettingsRoundTrip(t *testing.T) {
	def, _ := streaming.Lookup("custom")
	want := streaming.Config{
		Enabled: true, ListenIP: "192.168.191.2", Protocol: "both", Port: 26900, PortCount: 4,
		Upstream: "10.0.0.10:26900", UpstreamPort: 26900, Allow: []string{"10.0.0.0/8"},
		MaxConns: 64, MaxPerSource: 4, IdleSeconds: 90, MaxDatagram: 1200, ListIDs: []int64{3, 7},
	}
	got := streaming.ConfigFromSettings(def, streamingSettings(def, want))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}
