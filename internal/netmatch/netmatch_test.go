package netmatch

import (
	"net/netip"
	"testing"
)

func TestMapMatchesMostSpecificPrefix(t *testing.T) {
	m := New[string]()
	if err := m.AddCIDR("10.0.0.0/8", "broad"); err != nil {
		t.Fatal(err)
	}
	if err := m.AddCIDR("10.1.2.0/24", "narrow"); err != nil {
		t.Fatal(err)
	}
	got, ok := m.Match(netip.MustParseAddr("10.1.2.9"))
	if !ok || got != "narrow" {
		t.Fatalf("inside /24: got %q ok=%v", got, ok)
	}
	got, ok = m.Match(netip.MustParseAddr("10.9.9.9"))
	if !ok || got != "broad" {
		t.Fatalf("inside /8: got %q ok=%v", got, ok)
	}
	if _, ok := m.Match(netip.MustParseAddr("192.0.2.1")); ok {
		t.Fatal("unexpected match outside every prefix")
	}
}

func TestParsePrefixForms(t *testing.T) {
	cases := []struct{ in, want string }{
		{"192.0.2.5", "192.0.2.5/32"},
		{"192.0.2.5/24", "192.0.2.0/24"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"2001:db8::/32", "2001:db8::/32"},
	}
	for _, c := range cases {
		p, err := ParsePrefix(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if p.String() != c.want {
			t.Fatalf("%s: got %s want %s", c.in, p, c.want)
		}
	}
	if _, err := ParsePrefix("not-an-ip"); err == nil {
		t.Fatal("expected an error for garbage input")
	}
}

func TestAggregateDropsCoveredPrefixes(t *testing.T) {
	ps := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.1.0.0/16"),
		netip.MustParsePrefix("192.0.2.0/24"),
	}
	out := Aggregate(ps)
	if len(out) != 2 {
		t.Fatalf("got %d prefixes: %v", len(out), out)
	}
	for _, p := range out {
		if p.String() == "10.1.0.0/16" {
			t.Fatal("covered prefix was kept")
		}
	}
}
