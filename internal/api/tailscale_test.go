package api

import (
	"strings"
	"testing"
)

func TestValidateTailscale(t *testing.T) {
	cases := []struct {
		name      string
		req       tailscaleRequest
		kv        map[string]string
		available bool
		want      string
	}{
		{
			name:      "valid admin and proxy",
			req:       tailscaleRequest{AdminEnabled: true, ProxyEnabled: true, DNSEnabled: true},
			kv:        map[string]string{"gui_port": "8443", "wan_port": "443"},
			available: true,
		},
		{
			name: "unavailable tailscale",
			req:  tailscaleRequest{AdminEnabled: true},
			want: "not connected",
		},
		{
			name:      "dns preference without proxy",
			req:       tailscaleRequest{DNSEnabled: true},
			available: true,
		},

		{
			name:      "port collision",
			req:       tailscaleRequest{AdminEnabled: true, ProxyEnabled: true},
			kv:        map[string]string{"gui_port": "443", "wan_port": "443"},
			available: true,
			want:      "cannot share a port",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTailscale(tc.req, tc.kv, tc.available)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestSettingPort(t *testing.T) {
	if got := settingPort("", 8443); got != 8443 {
		t.Fatalf("empty port = %d, want fallback", got)
	}
	if got := settingPort("443", 8443); got != 443 {
		t.Fatalf("port = %d, want 443", got)
	}
	if got := settingPort("70000", 8443); got != 8443 {
		t.Fatalf("out-of-range port = %d, want fallback", got)
	}
}
