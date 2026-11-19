package crowdsec

import "testing"

func TestDecisionCIDR(t *testing.T) {
	cases := []struct {
		d    Decision
		want string
		ok   bool
	}{
		{Decision{Scope: "Ip", Value: "203.0.113.7"}, "203.0.113.7/32", true},
		{Decision{Scope: "Ip", Value: "2001:db8::1"}, "2001:db8::1/128", true},
		{Decision{Scope: "Range", Value: "203.0.113.0/24"}, "203.0.113.0/24", true},
		{Decision{Scope: "Country", Value: "RU"}, "", false},
		{Decision{Scope: "Ip", Value: "nonsense"}, "", false},
	}
	for _, c := range cases {
		got, ok := decisionCIDR(c.d)
		if ok != c.ok || got != c.want {
			t.Fatalf("%+v: got %q ok=%v want %q ok=%v", c.d, got, ok, c.want, c.ok)
		}
	}
}
