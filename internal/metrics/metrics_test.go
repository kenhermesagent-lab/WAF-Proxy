package metrics

import (
	"strings"
	"testing"
)

func TestParseDefaultRoute(t *testing.T) {
	const table = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
eth1	00000000	0102A8C0	0003	0	0	50	00000000	0	0	0
eth0	0001A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
docker0	00000000	00000000	0001	0	0	0	00000000	0	0	0
`
	if got := parseDefaultRoute(strings.NewReader(table)); got != "eth1" {
		t.Errorf("parseDefaultRoute = %q, want eth1 (lowest physical metric)", got)
	}
}

func TestParseDefaultRouteVirtualOnly(t *testing.T) {
	const table = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
docker0	00000000	00000000	0001	0	0	0	00000000	0	0	0
`
	if got := parseDefaultRoute(strings.NewReader(table)); got != "docker0" {
		t.Errorf("parseDefaultRoute = %q, want docker0 when it is the only default route", got)
	}
}

func TestParseDefaultRouteEmpty(t *testing.T) {
	if got := parseDefaultRoute(strings.NewReader("Iface\tDestination\tGateway\n")); got != "" {
		t.Errorf("parseDefaultRoute = %q, want empty", got)
	}
}

func TestIsVirtualInterface(t *testing.T) {
	cases := map[string]bool{
		"eth0":       false,
		"enp3s0":     false,
		"br0":        false,
		"tailscale0": false,
		"docker0":    true,
		"veth12a":    true,
		"virbr0":     true,
		"dummy0":     true,
	}
	for name, want := range cases {
		if got := isVirtualInterface(name); got != want {
			t.Errorf("isVirtualInterface(%q) = %v, want %v", name, got, want)
		}
	}
}
