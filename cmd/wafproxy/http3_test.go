package main

import (
	"strings"
	"testing"
)

func TestWANPort(t *testing.T) {
	cases := map[string]int{
		":443":                443,
		"192.168.1.10:8443":   8443,
		"[2001:db8::10]:9443": 9443,
	}
	for addr, want := range cases {
		got, err := wanPort(addr)
		if err != nil || got != want {
			t.Errorf("wanPort(%q) = %d, %v; want %d", addr, got, err, want)
		}
	}
	for _, addr := range []string{"", ":https", "localhost"} {
		if _, err := wanPort(addr); err == nil {
			t.Errorf("wanPort(%q) accepted an address without a usable port", addr)
		}
	}
}

// A UDP forwarder on the WAN port would bind before the QUIC socket, so the
// error has to name the card rather than report a bare bind failure.
func TestHTTP3StreamConflict(t *testing.T) {
	kv := map[string]string{
		"stream_valheim_enabled":    "1",
		"stream_valheim_protocol":   "udp",
		"stream_valheim_port":       "2456",
		"stream_valheim_port_count": "3",
	}
	err := http3StreamConflict(kv, 2457)
	if err == nil || !strings.Contains(err.Error(), "Valheim") {
		t.Fatalf("conflict on a UDP range = %v, want an error naming Valheim", err)
	}
	if err := http3StreamConflict(kv, 443); err != nil {
		t.Fatalf("port outside the range refused: %v", err)
	}

	// The same card over TCP shares the number with the TCP listener, which is
	// the normal case and not a conflict.
	kv["stream_valheim_protocol"] = "tcp"
	if err := http3StreamConflict(kv, 2456); err != nil {
		t.Fatalf("TCP card refused: %v", err)
	}

	// Disabled cards hold nothing.
	kv["stream_valheim_enabled"] = "0"
	kv["stream_valheim_protocol"] = "udp"
	if err := http3StreamConflict(kv, 2456); err != nil {
		t.Fatalf("disabled card refused: %v", err)
	}
}
