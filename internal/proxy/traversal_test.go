package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// A decoded ".." segment would be resolved by the backend, so the path that
// reaches it could differ from the one the WAF inspected. The edge canonicalises
// the path before checking and forwarding it.
func TestPipelineCanonicalisesDotSegments(t *testing.T) {
	h := newHarness(t)
	cases := map[string]string{
		"/foo/../etc/passwd":               "upstream:/etc/passwd:",
		"/..%2fetc%2fpasswd":               "upstream:/etc/passwd:",
		"/a/%2e%2e/etc/shadow":             "upstream:/etc/shadow:",
		`/..\etc\passwd`:                   "upstream:/etc/passwd:",
		"/%2e%2e/%2e%2e/%2e%2e/etc/passwd": "upstream:/etc/passwd:",
	}
	for path, want := range cases {
		rec := h.request(http.MethodGet, testHost, path, "", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200 from the test upstream", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s reached the upstream as %q, want %q", path, rec.Body.String(), want)
		}
		if strings.Contains(rec.Body.String(), "..") {
			t.Errorf("%s forwarded a dot segment: %q", path, rec.Body.String())
		}
	}
}

func TestCleanPathSegments(t *testing.T) {
	cases := map[string]string{
		"/":              "/",
		"/a/b":           "/a/b",
		"/a/./b":         "/a/b",
		"/a/../b":        "/b",
		"/a//b//":        "/a/b/",
		"/../../etc/x":   "/etc/x",
		"/a/..":          "/",
		`/a\..\b`:        "/b",
		"/.env":          "/.env",
		"/.well-known/x": "/.well-known/x",
		"/a.b/c..d":      "/a.b/c..d",
		"/../":           "/",
	}
	for in, want := range cases {
		got, ok := cleanPathSegments(in)
		if !ok {
			t.Errorf("%q rejected", in)
			continue
		}
		if got != want {
			t.Errorf("cleanPathSegments(%q) = %q, want %q", in, got, want)
		}
		for _, seg := range strings.Split(got, "/") {
			if seg == ".." {
				t.Errorf("cleaned path still has a dot segment: %q", got)
			}
		}
	}
	if _, ok := cleanPathSegments("/a\x00b"); ok {
		t.Error("a path with a NUL byte was accepted")
	}
}
