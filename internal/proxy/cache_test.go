package proxy

import (
	"net/http"
	"testing"
)

func TestVariesBeyondEncoding(t *testing.T) {
	cases := []struct {
		vary []string
		want bool
	}{
		{nil, false},
		{[]string{"Accept-Encoding"}, false},
		{[]string{"accept-encoding, Accept-Language"}, true},
		{[]string{"Accept-Language"}, true},
		{[]string{"*"}, true},
	}
	for _, c := range cases {
		h := http.Header{}
		for _, v := range c.vary {
			h.Add("Vary", v)
		}
		if got := variesBeyondEncoding(h); got != c.want {
			t.Errorf("variesBeyondEncoding(%v) = %v, want %v", c.vary, got, c.want)
		}
	}
}
