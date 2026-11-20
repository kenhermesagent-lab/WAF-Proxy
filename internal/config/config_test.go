package config

import "testing"

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
