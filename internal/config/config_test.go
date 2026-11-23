package config

import (
	"strings"
	"testing"
)

func TestIsLocalAddress(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{":8443", true},
		{"0.0.0.0:443", true},
		{"[::]:443", true},
		{"127.0.0.1:8443", true},
		{"localhost:8443", true},
		// TEST-NET-3 is never configured on a host running these tests.
		{"203.0.113.7:443", false},
		{"not-an-address", false},
	}
	for _, tc := range cases {
		if got := IsLocalAddress(tc.addr); got != tc.want {
			t.Errorf("IsLocalAddress(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestLoadRefusesAnUnsafeAutomaticFailover(t *testing.T) {
	t.Setenv("WAFPROXY_DATA_DIR", t.TempDir())
	t.Setenv("WAFPROXY_HA_AUTO_FAILOVER", "1")
	if _, err := Load(); err == nil {
		t.Fatal("automatic failover loaded without a witness")
	}
	t.Setenv("WAFPROXY_HA_WITNESS", "http://10.0.0.12:9444")
	t.Setenv("WAFPROXY_HA_WITNESS_TOKEN", strings.Repeat("a", 32))
	if _, err := Load(); err == nil {
		t.Fatal("automatic failover loaded without a fence command")
	}
	t.Setenv("WAFPROXY_HA_FENCE_COMMAND", "ipmitool power off {peer}")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("a complete automatic setup was refused: %v", err)
	}
	if !cfg.HAAutoFailover || cfg.HAFenceCommand == "" {
		t.Fatalf("automatic config = %+v", cfg)
	}
}

func TestLoadRequiresAConsoleHostForTLS(t *testing.T) {
	t.Setenv("WAFPROXY_DATA_DIR", t.TempDir())
	t.Setenv("WAFPROXY_LISTEN_GUI_TLS", "1")
	if _, err := Load(); err == nil {
		t.Fatal("console TLS started without a host")
	}
	t.Setenv("WAFPROXY_GUI_HOST", "console.example.com")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.ListenGUITLS || cfg.GUIHost != "console.example.com" {
		t.Fatalf("console TLS config = %+v", cfg)
	}
}
