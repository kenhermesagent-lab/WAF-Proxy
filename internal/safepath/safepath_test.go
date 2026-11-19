package safepath

import "testing"

func TestNext(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/private", "/private"},
		{"/private?x=1#top", "/private?x=1#top"},
		{"", "/"},
		{"https://evil.example/", "/"},
		{"//evil.example/", "/"},
		// Browsers treat a backslash as a slash, so this would otherwise become
		// the protocol-relative "//evil.example" after the redirect.
		{`/\evil.example/`, "/"},
		{"/\t/evil.example", "/"},
		{"/\r\nSet-Cookie: x=1", "/"},
	}
	for _, c := range cases {
		if got := Next(c.in); got != c.want {
			t.Errorf("Next(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
