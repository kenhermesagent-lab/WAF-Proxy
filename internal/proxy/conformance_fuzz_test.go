package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The cleaned path is what the console, the WAF and the upstream all act on, so
// it must always be absolute, free of dot segments and stable when cleaning it
// again (otherwise two passes would disagree about the same request).
func FuzzCleanPathSegments(f *testing.F) {
	for _, seed := range []string{
		"/", "/a/b", "/a/../b", "/..%2fetc%2fpasswd", "/a//b//", `\a\..\b`,
		"/.env", "/a.b/c..d", "/%2e%2e/%2e%2e/etc/passwd", "/a/\x00b", "",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, p string) {
		got, ok := cleanPathSegments(p)
		if !ok {
			if !strings.ContainsRune(p, 0) {
				t.Fatalf("cleanPathSegments(%q) was rejected without a NUL byte", p)
			}
			return
		}
		if !strings.HasPrefix(got, "/") {
			t.Fatalf("cleanPathSegments(%q) = %q, want an absolute path", p, got)
		}
		if strings.ContainsRune(got, 0) {
			t.Fatalf("cleanPathSegments(%q) kept a NUL byte", p)
		}
		if strings.Contains(got, "//") {
			t.Fatalf("cleanPathSegments(%q) = %q, want collapsed slashes", p, got)
		}
		for _, seg := range strings.Split(got, "/") {
			if seg == "." || seg == ".." {
				t.Fatalf("cleanPathSegments(%q) = %q, want no dot segments", p, got)
			}
		}
		again, ok := cleanPathSegments(got)
		if !ok || again != got {
			t.Fatalf("cleanPathSegments is not idempotent: %q -> %q -> %q", p, got, again)
		}
	})
}

// Header screening runs on every request before anything else, so it has to be
// total: no input may panic it, and no dropped header may survive it.
func FuzzInboundHeaderScreening(f *testing.F) {
	f.Add("X-Forwarded-For: 203.0.113.9\r\nForwarded: for=203.0.113.9")
	f.Add("X-Http-Method-Override: DELETE\r\nX-Original-Url: /admin")
	f.Add("X-Real-Ip:\r\nProxy: http://evil\r\nX-Forwarded-Host: evil.example")
	f.Fuzz(func(t *testing.T, raw string) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, line := range strings.Split(raw, "\r\n") {
			name, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			r.Header.Add(name, strings.TrimSpace(value))
		}
		cleanInboundHeaders(r)
		for _, name := range []string{
			"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip", "Forwarded",
			"X-Original-Url", "X-Rewrite-Url", "X-Http-Method-Override", "X-Forwarded-Server",
			"X-Forwarded-Port", "Proxy", "Proxy-Connection",
		} {
			if got := r.Header.Get(name); got != "" {
				t.Fatalf("cleanInboundHeaders kept %s: %q", name, got)
			}
		}
		_ = badRequestFraming(r)
	})
}
