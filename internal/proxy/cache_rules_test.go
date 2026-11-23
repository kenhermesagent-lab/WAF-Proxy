package proxy

import (
	"net/http"
	"testing"
)

func TestRangeRequestBypassesTheCache(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "http://site.test/file", nil)
	r.Header.Set("Range", "bytes=0-99")
	if cacheableRequest(r) {
		t.Fatal("a Range request was treated as cacheable")
	}
}

func TestCacheSkipsResponsesThatVaryOnMoreThanEncoding(t *testing.T) {
	c := newResponseCache(1<<20, 1<<20)
	h := http.Header{}
	h.Set("Cache-Control", "max-age=60")
	h.Set("Vary", "Cookie")
	c.put("site.test|/", http.StatusOK, h, []byte("body"))
	if _, ok := c.get("site.test|/"); ok {
		t.Fatal("a response varying on Cookie was cached")
	}
	h.Set("Vary", "Accept-Encoding")
	c.put("site.test|/enc", http.StatusOK, h, []byte("body"))
	if _, ok := c.get("site.test|/enc"); !ok {
		t.Fatal("a response varying only on encoding was not cached")
	}
}
