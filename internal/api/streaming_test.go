package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"strconv"
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

// freeBothRange finds n consecutive numbers a TCP listener and a UDP socket can
// each bind, so a handler test can start a real "both" range.
func freeBothRange(t *testing.T, n int) int {
	t.Helper()
	for base := 34000; base+n-1 < 65000; base++ {
		tcp := make([]net.Listener, 0, n)
		ok := true
		for i := 0; i < n; i++ {
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", base+i))
			if err != nil {
				ok = false
				break
			}
			tcp = append(tcp, ln)
		}
		for _, ln := range tcp {
			_ = ln.Close()
		}
		if !ok {
			continue
		}
		udp := make([]*net.UDPConn, 0, n)
		for i := 0; i < n; i++ {
			pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: base + i})
			if err != nil {
				ok = false
				break
			}
			udp = append(udp, pc)
		}
		for _, pc := range udp {
			_ = pc.Close()
		}
		if ok {
			return base
		}
	}
	t.Fatalf("no run of %d free TCP+UDP ports", n)
	return 0
}

// A save with protocol=both over a range binds both sockets, persists every new
// key and reports the merged listener back to the page.
func TestStreamingPutBindsBothProtocolsOverARange(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	m := streaming.New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.SetStreaming(m)
	t.Cleanup(m.Close)

	base := freeBothRange(t, 3)
	body := fmt.Sprintf(`{"enabled":true,"listen_ip":"127.0.0.1","protocol":"both",`+
		`"port":%d,"port_count":3,"upstream":"10.0.0.10:%d","upstream_port":%d,`+
		`"allow":"10.0.0.0/8","max_conns":32,"max_per_source":2,"idle_seconds":90,`+
		`"max_datagram":1200,"list_ids":[]}`, base, base, base)
	rec := authed(t, srv, token, csrf, http.MethodPut, "/api/streaming/custom", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/streaming/custom = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Applied bool   `json:"applied"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Applied || resp.Error != "" {
		t.Fatalf("apply = %+v, want the both range bound", resp)
	}

	kv, err := st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"stream_custom_protocol":       "both",
		"stream_custom_port":           strconv.Itoa(base),
		"stream_custom_port_count":     "3",
		"stream_custom_upstream":       "10.0.0.10:" + strconv.Itoa(base),
		"stream_custom_upstream_port":  strconv.Itoa(base),
		"stream_custom_max_per_source": "2",
		"stream_custom_idle_seconds":   "90",
		"stream_custom_max_datagram":   "1200",
	}
	for key, value := range want {
		if kv[key] != value {
			t.Errorf("%s = %q, want %q", key, kv[key], value)
		}
	}

	rec = authed(t, srv, token, csrf, http.MethodGet, "/api/streaming", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/streaming = %d: %s", rec.Code, rec.Body.String())
	}
	var view struct{ Services []streaming.Status }
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode streaming view: %v", err)
	}
	var custom streaming.Status
	for _, s := range view.Services {
		if s.ID == "custom" {
			custom = s
		}
	}
	if custom.Protocol != "both" || custom.PortCount != 3 || !custom.Bound {
		t.Fatalf("status = %+v, want both bound over three ports", custom)
	}
	if wantAddr := fmt.Sprintf("127.0.0.1:%d-%d tcp+udp", base, base+2); custom.ListenAddr != wantAddr {
		t.Fatalf("listen_addr = %q, want %q", custom.ListenAddr, wantAddr)
	}
}

// An unsaved card opens with the preset's protocol and range, and the upstream
// address the setup wizard chose.
func TestStreamingDefaultsComeFromThePreset(t *testing.T) {
	srv := &Server{}
	valheim, _ := streaming.Lookup("valheim")
	got := srv.streamingDefaults(valheim, map[string]string{"wan_ip": "192.168.191.2", "lan_ip": "10.0.0.10"})
	if got["protocol"] != "udp" || got["port"] != 2456 || got["port_count"] != 3 || got["upstream_port"] != 2456 {
		t.Fatalf("valheim defaults = %v", got)
	}
	if got["upstream"] != "10.0.0.10:2456" || got["listen_ip"] != "192.168.191.2" {
		t.Fatalf("address defaults = %v", got)
	}

	// The custom card has no port of its own, so it prefills the bare address.
	custom, _ := streaming.Lookup("custom")
	if got := srv.streamingDefaults(custom, map[string]string{"lan_ip": "10.0.0.10"}); got["upstream"] != "10.0.0.10" {
		t.Fatalf("custom upstream default = %v", got["upstream"])
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
