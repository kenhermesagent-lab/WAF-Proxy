package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"
)

const (
	encBrotli   = "br"
	encGzip     = "gzip"
	encIdentity = "identity"

	// cachedBrotliQuality trades ratio for CPU on the hit path; the table it
	// was picked from is in docs/BENCHMARKS.md.
	cachedBrotliQuality = 4
)

type cacheEntry struct {
	status  int
	header  http.Header
	body    []byte
	expires time.Time
	// One encoded copy per encoding, built by the first hit that asks for it.
	mu           sync.Mutex
	encoded      map[string][]byte
	once         map[string]*sync.Once
	variantBytes atomic.Int64
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
	// hits and misses are per hostname for the capacity panel. They never
	// shrink, so a site that stopped caching still reports its ratio.
	hits   map[string]int64
	misses map[string]int64
	now    func() time.Time
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
		perHost: quota, hostBytes: map[string]int64{},
		hits: map[string]int64{}, misses: map[string]int64{}, now: time.Now}
}

func cacheHost(key string) string {
	if i := strings.IndexByte(key, '|'); i >= 0 {
		return key[:i]
	}
	return key
}

// cacheKey names one representation of a URL: the identity bytes. Encoded
// bodies are variants inside the entry, so clients that order or weight
// Accept-Encoding differently share one upstream fetch.
func cacheKey(r *http.Request) string {
	return r.Host + "|" + r.URL.RequestURI()
}

// negotiateEncoding picks the body encoding to send. identity is acceptable
// unless the client excludes it (identity;q=0 or *;q=0), but it ranks below
// any encoding the client names, so "gzip;q=0.5" gets gzip. br wins a tie
// with gzip. ok is false when the client accepts nothing we can send.
func negotiateEncoding(accept string) (enc string, ok bool) {
	if strings.TrimSpace(accept) == "" {
		return encIdentity, true
	}
	weights := map[string]float64{}
	for _, part := range strings.Split(accept, ",") {
		fields := strings.Split(part, ";")
		name := strings.ToLower(strings.TrimSpace(fields[0]))
		if name == "" {
			continue
		}
		weight := 1.0
		for _, param := range fields[1:] {
			if q, has := strings.CutPrefix(strings.ToLower(strings.TrimSpace(param)), "q="); has {
				v, err := strconv.ParseFloat(q, 64)
				if err != nil || v < 0 || v > 1 {
					weight = 0
					break
				}
				weight = v
			}
		}
		if old, seen := weights[name]; !seen || weight > old {
			weights[name] = weight
		}
	}
	star, hasStar := weights["*"]
	weightOf := func(name string, fallback float64) float64 {
		if v, ok := weights[name]; ok {
			return v
		}
		if hasStar {
			return star
		}
		return fallback
	}
	best, bestQ := "", 0.0
	for _, name := range []string{encBrotli, encGzip} {
		if q := weightOf(name, 0); q > bestQ {
			best, bestQ = name, q
		}
	}
	if q := weightOf(encIdentity, 0.001); q > bestQ {
		return encIdentity, true
	}
	if best == "" {
		return "", false
	}
	return best, true
}

// encodedBodies counts compressions, so a test can prove a variant is built
// once per entry rather than once per hit.
var encodedBodies atomic.Int64

var brotliPool = sync.Pool{New: func() any { return brotli.NewWriterLevel(io.Discard, cachedBrotliQuality) }}
var gzipPool = sync.Pool{New: func() any { return gzip.NewWriter(io.Discard) }}

func encodeBody(enc string, body []byte) []byte {
	encodedBodies.Add(1)
	var buf bytes.Buffer
	switch enc {
	case encBrotli:
		w := brotliPool.Get().(*brotli.Writer)
		w.Reset(&buf)
		_, _ = w.Write(body)
		_ = w.Close()
		brotliPool.Put(w)
	case encGzip:
		w := gzipPool.Get().(*gzip.Writer)
		w.Reset(&buf)
		_, _ = w.Write(body)
		_ = w.Close()
		gzipPool.Put(w)
	default:
		return body
	}
	return buf.Bytes()
}

// variant returns the body encoded as enc, built at most once per encoding and
// charged to the cache after the first hit that asks for it.
func (c *responseCache) variant(key string, e *cacheEntry, enc string) []byte {
	e.mu.Lock()
	if b, ok := e.encoded[enc]; ok {
		e.mu.Unlock()
		return b
	}
	once, ok := e.once[enc]
	if !ok {
		once = &sync.Once{}
		e.once[enc] = once
	}
	e.mu.Unlock()
	once.Do(func() {
		b := encodeBody(enc, e.body)
		if !c.countVariant(key, e, int64(len(b))) {
			return
		}
		e.mu.Lock()
		e.encoded[enc] = b
		e.mu.Unlock()
	})
	e.mu.Lock()
	b := e.encoded[enc]
	e.mu.Unlock()
	if b == nil {
		// The host quota refused to keep it, so this hit compresses its own copy.
		b = encodeBody(enc, e.body)
	}
	return b
}

// countVariant charges an encoded copy to the cache and drops entries until the
// total fits again. It reports whether the variant was kept: one that does not
// fit the host's quota is served once without being stored. An entry evicted
// while its variant was built is not charged.
func (c *responseCache) countVariant(key string, e *cacheEntry, size int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries[key] != e {
		return false
	}
	host := cacheHost(key)
	if c.hostBytes[host]+size > c.perHost {
		return false
	}
	e.variantBytes.Add(size)
	c.bytes += size
	c.hostBytes[host] += size
	for c.bytes > c.maxSize && len(c.entries) > 0 {
		c.evictOldestLocked()
	}
	return true
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
	host := cacheHost(key)
	e, ok := c.entries[key]
	if ok && !c.now().After(e.expires) {
		c.hits[host]++
		return e, true
	}
	c.misses[host]++
	if ok {
		c.removeLocked(key, e)
	}
	return nil, false
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
		expires: c.now().Add(time.Duration(maxAge) * time.Second),
		encoded: map[string][]byte{}, once: map[string]*sync.Once{}}
	c.bytes += size
	c.hostBytes[host] += size
}

func (c *responseCache) removeLocked(key string, e *cacheEntry) {
	host := cacheHost(key)
	// Variants belong to the entry, so eviction takes them with it.
	size := int64(len(e.body)) + e.variantBytes.Load()
	c.bytes -= size
	c.hostBytes[host] -= size
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

// cacheHostStats is one hostname's share of the cache.
type cacheHostStats struct {
	Bytes, Hits, Misses int64
}

// snapshot reports the cache totals and one line per hostname.
func (c *responseCache) snapshot() (bytes, max int64, hosts map[string]cacheHostStats) {
	c.mu.Lock()
	defer c.mu.Unlock()
	hosts = make(map[string]cacheHostStats, len(c.hostBytes))
	for h, b := range c.hostBytes {
		hosts[h] = cacheHostStats{Bytes: b}
	}
	for h, n := range c.hits {
		s := hosts[h]
		s.Hits = n
		hosts[h] = s
	}
	for h, n := range c.misses {
		s := hosts[h]
		s.Misses = n
		hosts[h] = s
	}
	return c.bytes, c.maxSize, hosts
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

// serveCached writes a stored entry in the encoding the client accepts.
func (e *edge) serveCached(rw http.ResponseWriter, key string, entry *cacheEntry, enc string) {
	hdr := entry.header
	body := entry.body
	if enc != encIdentity && shouldCompress(entry.status, entry.header) {
		// The stored header is shared, so the encoded hit writes a copy.
		hdr = entry.header.Clone()
		body = e.cache.variant(key, entry, enc)
		hdr.Set("Content-Encoding", enc)
		hdr.Set("Vary", "Accept-Encoding")
	}
	for k, vals := range hdr {
		rw.Header()[k] = append([]string(nil), vals...)
	}
	rw.WriteHeader(entry.status)
	_, _ = rw.Write(body)
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
		// A body the upstream already encoded cannot be stored as identity and
		// re-encoded later. Read here, before the outer writer changes it.
		ce := w.Header().Get("Content-Encoding")
		if code != http.StatusOK || len(w.Header().Get("Cache-Control")) == 0 ||
			(ce != "" && !strings.EqualFold(ce, encIdentity)) {
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
