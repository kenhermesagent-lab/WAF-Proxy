package proxy

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/andybalholm/brotli"
)

func TestNegotiateEncoding(t *testing.T) {
	cases := []struct {
		accept string
		want   string
		ok     bool
	}{
		{"", encIdentity, true},
		{"identity", encIdentity, true},
		{"gzip", encGzip, true},
		{"br", encBrotli, true},
		{"gzip, deflate, br", encBrotli, true},
		{"br;q=1, gzip;q=0.5", encBrotli, true},
		{"br;q=0.2, gzip;q=0.9", encGzip, true},
		{"br;q=0, gzip", encGzip, true},
		{"*", encBrotli, true},
		{"gzip;q=0, *;q=0", "", false},
		{"identity;q=0, br;q=0, gzip;q=0", "", false},
	}
	for _, c := range cases {
		got, ok := negotiateEncoding(c.accept)
		if got != c.want || ok != c.ok {
			t.Errorf("negotiateEncoding(%q) = %q, %v; want %q, %v", c.accept, got, ok, c.want, c.ok)
		}
	}
}

func decode(t *testing.T, enc string, body []byte) string {
	t.Helper()
	var r io.Reader
	switch enc {
	case encBrotli:
		r = brotli.NewReader(bytes.NewReader(body))
	case encGzip:
		gz, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("%s reader: %v", enc, err)
		}
		defer gz.Close()
		r = gz
	default:
		return string(body)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("%s decode: %v", enc, err)
	}
	return string(out)
}

// One entry answers every encoding: the second and third client reuse the
// upstream body and only the first brotli hit pays for compression.
func TestCachedAssetServesOneVariantPerEncoding(t *testing.T) {
	h := newHarness(t)
	miss := h.request(http.MethodGet, testHost, "/cache", "", map[string]string{"Accept-Encoding": "gzip, deflate, br"})
	if miss.Code != http.StatusOK {
		t.Fatalf("miss status = %d", miss.Code)
	}
	before := encodedBodies.Load()

	br := h.request(http.MethodGet, testHost, "/cache", "", map[string]string{"Accept-Encoding": "gzip, deflate, br"})
	if got := br.Header().Get("Content-Encoding"); got != encBrotli {
		t.Fatalf("brotli hit Content-Encoding = %q", got)
	}
	if got := decode(t, encBrotli, br.Body.Bytes()); got != decode(t, encGzip, miss.Body.Bytes()) {
		t.Fatalf("brotli hit decodes to %q", got)
	}

	// Same representation, reordered and reweighted header: no new compression.
	again := h.request(http.MethodGet, testHost, "/cache", "", map[string]string{"Accept-Encoding": "br;q=1, gzip;q=0.5"})
	if got := again.Header().Get("Content-Encoding"); got != encBrotli {
		t.Fatalf("reordered hit Content-Encoding = %q", got)
	}
	if !bytes.Equal(again.Body.Bytes(), br.Body.Bytes()) {
		t.Fatal("the second brotli hit produced different bytes")
	}
	if added := encodedBodies.Load() - before; added != 1 {
		t.Fatalf("encoded %d bodies across three hits, want 1", added)
	}

	gz := h.request(http.MethodGet, testHost, "/cache", "", map[string]string{"Accept-Encoding": "gzip"})
	if got := gz.Header().Get("Content-Encoding"); got != encGzip {
		t.Fatalf("gzip hit Content-Encoding = %q", got)
	}
	if got := decode(t, encGzip, gz.Body.Bytes()); got != "upstream:/cache:"+testIP {
		t.Fatalf("gzip hit decodes to %q", got)
	}
	if h.hits.Load() != 1 {
		t.Fatalf("upstream hits = %d for four encodings of one asset, want 1", h.hits.Load())
	}
}

func TestCacheRefusesAnUnacceptableEncoding(t *testing.T) {
	h := newHarness(t)
	rec := h.request(http.MethodGet, testHost, "/cache", "", map[string]string{
		"Accept-Encoding": "identity;q=0, br;q=0, gzip;q=0"})
	if rec.Code != http.StatusNotAcceptable {
		t.Fatalf("status = %d, want 406", rec.Code)
	}
	if got := rec.Header().Get("Vary"); got != "Accept-Encoding" {
		t.Fatalf("Vary = %q", got)
	}
	if h.hits.Load() != 0 {
		t.Fatalf("upstream was asked for a body nobody can read")
	}
}

func TestVariantBytesAreChargedToTheCache(t *testing.T) {
	c := newResponseCache(1<<20, 1<<20)
	payload := bytes.Repeat([]byte("compress me "), 4096)
	c.put("site.test|/", http.StatusOK, cacheableHeader("60"), payload)
	e, ok := c.get("site.test|/")
	if !ok {
		t.Fatal("entry was not cached")
	}

	v := c.variant("site.test|/", e, encBrotli)
	if len(v) == 0 {
		t.Fatal("brotli variant is empty")
	}
	if got := c.variant("site.test|/", e, encBrotli); !bytes.Equal(got, v) {
		t.Fatal("the variant changed between hits")
	}
	c.mu.Lock()
	want := int64(len(payload) + len(v))
	got := c.bytes
	c.mu.Unlock()
	if got != want {
		t.Fatalf("cache holds %d bytes, want %d (identity plus one variant)", got, want)
	}
	c.purge("site.test")
	c.mu.Lock()
	got, hosts := c.bytes, len(c.hostBytes)
	c.mu.Unlock()
	if got != 0 || hosts != 0 {
		t.Fatalf("after purge: %d bytes and %d hosts", got, hosts)
	}
}

// BenchmarkBrotliQuality picks cachedBrotliQuality: ratio against CPU cost on a
// 64 KiB compressible body, the asset size the A4 exit criterion names.
func BenchmarkBrotliQuality(b *testing.B) {
	var page bytes.Buffer
	for page.Len() < 64<<10 {
		n := page.Len()
		fmt.Fprintf(&page, "<div class=\"row row-%d\" data-id=\"%d\"><span>cached asset %d</span></div>\n", n, n*7919%100000, n*104729%100000)
	}
	body := page.Bytes()[:64<<10]
	b.SetBytes(int64(len(body)))
	for _, level := range []int{1, 4, 9} {
		b.Run(string(rune('0'+level)), func(b *testing.B) {
			var out bytes.Buffer
			w := brotli.NewWriterLevel(&out, level)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out.Reset()
				w.Reset(&out)
				_, _ = w.Write(body)
				_ = w.Close()
			}
			b.ReportMetric(float64(out.Len()), "bytes")
		})
	}
}
