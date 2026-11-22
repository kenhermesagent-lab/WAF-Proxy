package proxy

import (
	"net/http"
	"testing"
)

func cacheableHeader(maxAge string) http.Header {
	h := http.Header{}
	h.Set("Cache-Control", "max-age="+maxAge)
	return h
}

func TestCachePerHostQuotaIsolatesSites(t *testing.T) {
	c := newResponseCache(100, 60)
	big := make([]byte, 40)
	c.put("a.test|/one", http.StatusOK, cacheableHeader("60"), big)
	c.put("a.test|/two", http.StatusOK, cacheableHeader("60"), big)
	if _, ok := c.get("a.test|/two"); ok {
		t.Fatal("a host exceeded its per-host quota")
	}
	c.put("b.test|/one", http.StatusOK, cacheableHeader("60"), big)
	if _, ok := c.get("b.test|/one"); !ok {
		t.Fatal("one host's quota blocked another host")
	}
}

func TestCacheEvictsWhenTheTotalBudgetIsFull(t *testing.T) {
	c := newResponseCache(70, 70)
	c.put("a.test|/one", http.StatusOK, cacheableHeader("60"), make([]byte, 40))
	c.put("b.test|/two", http.StatusOK, cacheableHeader("60"), make([]byte, 40))
	if _, ok := c.get("a.test|/one"); ok {
		t.Fatal("the oldest entry was not evicted to stay inside the total budget")
	}
	if _, ok := c.get("b.test|/two"); !ok {
		t.Fatal("the newest entry was not cached")
	}
	if c.bytes > c.maxSize {
		t.Fatalf("cache holds %d bytes over a %d budget", c.bytes, c.maxSize)
	}
}

func TestCachePurgeTargetsOneHost(t *testing.T) {
	c := newResponseCache(200, 200)
	c.put("a.test|/one", http.StatusOK, cacheableHeader("60"), []byte("a"))
	c.put("b.test|/one", http.StatusOK, cacheableHeader("60"), []byte("b"))
	if n := c.purge("a.test"); n != 1 {
		t.Fatalf("purge removed %d entries", n)
	}
	if _, ok := c.get("a.test|/one"); ok {
		t.Fatal("purged host still cached")
	}
	if _, ok := c.get("b.test|/one"); !ok {
		t.Fatal("purge removed another host's entry")
	}
	if n := c.purge(""); n != 1 {
		t.Fatalf("purge-all removed %d entries", n)
	}
}
