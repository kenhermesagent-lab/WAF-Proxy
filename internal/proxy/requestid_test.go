package proxy

import (
	"net/http"
	"strings"
	"testing"
)

func TestRequestIDKeepsSafeClientValues(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "http://site.test/", nil)
	r.Header.Set("X-Request-Id", "edge-7f3a.2")
	if got := requestIDFor(r); got != "edge-7f3a.2" {
		t.Fatalf("client request id replaced with %q", got)
	}
}

func TestRequestIDReplacesUnsafeOrLongValues(t *testing.T) {
	cases := []string{"bad id with spaces", strings.Repeat("a", 65), "<script>", "line\nbreak"}
	for _, value := range cases {
		r, _ := http.NewRequest(http.MethodGet, "http://site.test/", nil)
		r.Header.Set("X-Request-Id", value)
		got := requestIDFor(r)
		if got == value || len(got) != 16 {
			t.Fatalf("unsafe id %q was not replaced (got %q)", value, got)
		}
	}
}

func TestRequestIDGeneratedWhenAbsent(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "http://site.test/", nil)
	if got := requestIDFor(r); len(got) != 16 {
		t.Fatalf("generated id %q", got)
	}
}
