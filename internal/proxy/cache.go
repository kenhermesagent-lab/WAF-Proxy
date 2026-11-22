package proxy

import (
	"bufio"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type cacheEntry struct {
	status  int
	header  http.Header
	body    []byte
	expires time.Time
}

// responseCache stores only explicitly cacheable GET responses: no cookies, no
// authorization, and a positive max-age. It is deliberately conservative.
type responseCache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
	bytes   int64
	maxSize int64
	// perHost caps one hostname so a single site cannot fill the cache.
	perHost   int64
	hostBytes map[string]int64
	now       func() time.Time
}

func newResponseCache(maxSize int64, perHost ...int64) *responseCache {
	if maxSize <= 0 {
		maxSize = 32 << 20
	}
	quota := maxSize
	if len(perHost) > 0 && perHost[0] > 0 {
		quota = perHost[0]
	}
	return &responseCache{entries: map[string]*cacheEntry{}, maxSize: maxSize,
		perHost: quota, hostBytes: map[string]int64{}, now: time.Now}
}

func cacheHost(key string) string {
	if i := strings.IndexByte(key, '|'); i >= 0 {
		return key[:i]
	}
	return key
}

func cacheKey(r *http.Request) string {
	return r.Host + "|" + r.URL.RequestURI() + "|" + r.Header.Get("Accept-Encoding")
}

// variesBeyondEncoding reports whether a Vary header names a request field
// other than Accept-Encoding. The cache key already contains the encoding, so
// Vary: Accept-Encoding alone is safe to store.
func variesBeyondEncoding(h http.Header) bool {
	for _, value := range h.Values("Vary") {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" || strings.EqualFold(part, "Accept-Encoding") {
				continue
			}
			return true
		}
	}
	return false
}

func cacheableRequest(r *http.Request) bool {
	// HEAD responses have no body, so caching them under the same key as GET
	// would poison the cache with an empty body. GET only.
	if r.Method != http.MethodGet {
		return false
	}
	if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" ||
		r.Header.Get("Range") != "" {
		return false
	}
	return true
}

func (c *responseCache) get(key string) (*cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if c.now().After(e.expires) {
		c.removeLocked(key, e)
		return nil, false
	}
	return e, true
}

func (c *responseCache) put(key string, status int, header http.Header, body []byte) {
	if status != http.StatusOK || header.Get("Set-Cookie") != "" || header.Get("Cache-Control") == "" {
		return
	}
	maxAge := 0
	for _, part := range strings.Split(header.Get("Cache-Control"), ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if strings.HasPrefix(part, "max-age=") {
			if v, err := strconv.Atoi(part[len("max-age="):]); err == nil {
				maxAge = v
			}
		}
		if part == "no-store" || part == "private" || part == "no-cache" {
			return
		}
	}
	if maxAge <= 0 || maxAge > 300 || len(body) > 512*1024 {
		return
	}
	// A response that varies on anything other than the encoding is not a
	// single representation, so caching it under one key could serve, for
	// example, the wrong language to the next visitor.
	if variesBeyondEncoding(header) {
		return
	}
	cp := header.Clone()
	for _, k := range hopHeaders {
		cp.Del(k)
	}
	cp.Del("Content-Length")
	size := int64(len(body))
	host := cacheHost(key)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hostBytes[host]+size > c.perHost {
		return
	}
	if old, ok := c.entries[key]; ok {
		c.removeLocked(key, old)
	}
	c.evictExpiredLocked()
	for c.bytes+size > c.maxSize && len(c.entries) > 0 {
		c.evictOldestLocked()
	}
	if c.bytes+size > c.maxSize {
		return
	}
	c.entries[key] = &cacheEntry{status: status, header: cp, body: body,
		expires: c.now().Add(time.Duration(maxAge) * time.Second)}
	c.bytes += size
	c.hostBytes[host] += size
}

func (c *responseCache) removeLocked(key string, e *cacheEntry) {
	host := cacheHost(key)
	c.bytes -= int64(len(e.body))
	c.hostBytes[host] -= int64(len(e.body))
	if c.hostBytes[host] <= 0 {
		delete(c.hostBytes, host)
	}
	delete(c.entries, key)
}

func (c *responseCache) evictExpiredLocked() {
	now := c.now()
	for key, e := range c.entries {
		if now.After(e.expires) {
			c.removeLocked(key, e)
		}
	}
}

func (c *responseCache) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for key, e := range c.entries {
		if oldestKey == "" || e.expires.Before(oldest) {
			oldestKey, oldest = key, e.expires
		}
	}
	if oldestKey != "" {
		c.removeLocked(oldestKey, c.entries[oldestKey])
	}
}

// purge drops every cached response for a host, or everything when host is
// empty, and returns how many entries were removed.
func (c *responseCache) purge(host string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for key, e := range c.entries {
		if host == "" || strings.EqualFold(cacheHost(key), host) {
			c.removeLocked(key, e)
			removed++
		}
	}
	return removed
}

// cacheWriter tees a response into the cache while streaming it to the client.
type cacheWriter struct {
	http.ResponseWriter
	key     string
	cache   *responseCache
	buf     []byte
	status  int
	decided bool
	skip    bool
}

func (w *cacheWriter) WriteHeader(code int) {
	if !w.decided {
		w.decided = true
		w.status = code
		if code != http.StatusOK || len(w.Header().Get("Cache-Control")) == 0 {
			w.skip = true
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *cacheWriter) Write(b []byte) (int, error) {
	if !w.decided {
		w.WriteHeader(http.StatusOK)
	}
	if !w.skip && len(w.buf)+len(b) <= 512*1024 {
		w.buf = append(w.buf, b...)
	} else {
		w.skip = true
	}
	return w.ResponseWriter.Write(b)
}

func (w *cacheWriter) headersSent() bool { return w.decided }

func (w *cacheWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *cacheWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	w.skip = true
	return hj.Hijack()
}

func (w *cacheWriter) finish() {
	if w.skip || w.status != http.StatusOK {
		return
	}
	h := w.Header()
	if variesBeyondEncoding(h) {
		return
	}
	h = h.Clone()
	h.Del("Content-Encoding")
	h.Del("Content-Length")
	h.Del("Transfer-Encoding")
	h.Del("Vary")
	w.cache.put(w.key, w.status, h, w.buf)
}
