package proxy

import (
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// leakedHeaders identify the stack and are always removed.
var leakedHeaders = []string{
	"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator",
	"X-Drupal-Cache", "X-Runtime", "X-Varnish", "Via", "X-Cache", "X-Debug-Token", "X-Served-By",
}

// responseWriter captures status and size and applies fingerprint hygiene.
type responseWriter struct {
	http.ResponseWriter
	status      int
	size        int64
	wroteHeader bool
	strict      bool
	requestID   string
	// protection is the per-proxy hardening profile, and secure reports
	// whether this request arrived over TLS (HSTS is meaningless otherwise).
	protection *model.ProtectionProfile
	secure     bool
}

func (w *responseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = code
	h := w.Header()
	for _, k := range hopHeaders {
		h.Del(k)
	}
	if w.strict {
		for _, k := range leakedHeaders {
			h.Del(k)
		}
	}
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	if w.protection != nil {
		applyProtection(h, w.protection, w.secure)
	}
	if w.requestID != "" {
		h.Set("X-Request-Id", w.requestID)
	}
	w.ResponseWriter.WriteHeader(code)
}

// applyProtection writes the profile's response hardening. It runs after the
// baseline headers, so an explicit "off" in the profile removes a default the
// proxy would otherwise set.
func applyProtection(h http.Header, p *model.ProtectionProfile, secure bool) {
	if p.HideServer {
		for _, k := range leakedHeaders {
			h.Del(k)
		}
	}
	setOrClear := func(name, value string) {
		if strings.TrimSpace(value) == "" {
			h.Del(name)
			return
		}
		h.Set(name, value)
	}
	if !p.NoSniff {
		h.Del("X-Content-Type-Options")
	}
	setOrClear("Referrer-Policy", p.ReferrerPolicy)
	switch p.FrameOptions {
	case "deny":
		h.Set("X-Frame-Options", "DENY")
	case "sameorigin":
		h.Set("X-Frame-Options", "SAMEORIGIN")
	default:
		h.Del("X-Frame-Options")
	}
	setOrClear("Content-Security-Policy", p.CSP)
	setOrClear("Permissions-Policy", p.PermissionsPolicy)
	if secure && p.HSTS {
		value := "max-age=31536000"
		if p.HSTSSubdomains {
			value += "; includeSubDomains"
		}
		h.Set("Strict-Transport-Security", value)
	} else {
		h.Del("Strict-Transport-Security")
	}
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.size += int64(n)
	return n, err
}

func (w *responseWriter) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func (w *responseWriter) Size() int64 { return w.size }

// headersSent reports whether the status line has gone out. The reverse proxy
// uses it to decide whether an upstream failure can still become an error page.
func (w *responseWriter) headersSent() bool { return w.wroteHeader }

// errResponseCap is returned when an upstream response passes the profile's
// ceiling. The reverse proxy stops reading on it, which cuts the response.
var errResponseCap = errors.New("upstream response exceeded the profile limit")

// capWriter enforces a response ceiling. A declared length above the limit is
// refused before any body is sent; a streamed body is cut the moment it passes,
// so an upstream cannot stream without bound through the proxy.
type capWriter struct {
	http.ResponseWriter
	limit int64
	n     int64
	sent  bool
	// refused is set when the declared length was over the ceiling and the
	// refusal page replaced the response. over is set when a streamed body had
	// to be cut, which the caller turns into an aborted connection because
	// there is no status left to change.
	refused   bool
	over      bool
	discarded int64
	// trip runs once, when the ceiling is hit, so the caller can discard a
	// partial cache entry and record what happened.
	trip func()
}

func (w *capWriter) WriteHeader(code int) {
	if w.sent || w.over || w.refused {
		return
	}
	if cl := w.Header().Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil && n > w.limit {
			w.refused = true
			for name := range w.Header() {
				w.Header().Del(name)
			}
			w.trip()
			uniformError(w.ResponseWriter, http.StatusBadGateway)
			return
		}
	}
	w.sent = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *capWriter) Write(b []byte) (int, error) {
	if w.refused {
		// The refusal page has been written, so the body is swallowed until the
		// reverse proxy finishes and the response is flushed. A lying upstream
		// that keeps sending past a generous bound ends the connection instead.
		w.discarded += int64(len(b))
		if w.discarded > 4<<20 {
			return 0, errResponseCap
		}
		return len(b), nil
	}
	if w.over {
		return 0, errResponseCap
	}
	if !w.sent {
		w.WriteHeader(http.StatusOK)
	}
	if w.n+int64(len(b)) > w.limit {
		w.over = true
		w.trip()
		return 0, errResponseCap
	}
	n, err := w.ResponseWriter.Write(b)
	w.n += int64(n)
	return n, err
}

func (w *capWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *capWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijacking not supported")
	}
	w.sent = true
	return hj.Hijack()
}

func (w *capWriter) headersSent() bool { return w.sent || w.over || w.refused }

func (w *responseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijacking not supported")
	}
	// A hijacked connection never writes a status line, so the log would call
	// a protocol switch a 200 without this.
	if !w.wroteHeader {
		w.status = http.StatusSwitchingProtocols
	}
	return hj.Hijack()
}

// gzipWriter compresses compressible responses when the client accepts it.
type gzipWriter struct {
	http.ResponseWriter
	accept      string
	gz          *gzip.Writer
	compressing bool
	decided     bool
}

func newGzipWriter(w http.ResponseWriter, accept string) *gzipWriter {
	return &gzipWriter{ResponseWriter: w, accept: accept}
}

func (w *gzipWriter) WriteHeader(code int) {
	if !w.decided {
		w.decided = true
		h := w.Header()
		if shouldCompress(code, h) && strings.Contains(w.accept, "gzip") {
			w.compressing = true
			h.Set("Content-Encoding", "gzip")
			h.Del("Content-Length")
			h.Add("Vary", "Accept-Encoding")
			w.gz = gzip.NewWriter(w.ResponseWriter)
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *gzipWriter) Write(b []byte) (int, error) {
	if !w.decided {
		w.WriteHeader(http.StatusOK)
	}
	if w.compressing {
		return w.gz.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

func (w *gzipWriter) headersSent() bool { return w.decided }

func (w *gzipWriter) Close() error {
	if w.gz != nil {
		return w.gz.Close()
	}
	return nil
}

func (w *gzipWriter) Flush() {
	if w.gz != nil {
		_ = w.gz.Flush()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *gzipWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijacking not supported")
	}
	w.decided = true
	return hj.Hijack()
}

func shouldCompress(status int, h http.Header) bool {
	if status != http.StatusOK {
		return false
	}
	if h.Get("Content-Encoding") != "" || h.Get("Content-Range") != "" {
		return false
	}
	ct := h.Get("Content-Type")
	return strings.HasPrefix(ct, "text/") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "xml") ||
		strings.Contains(ct, "svg")
}

// uniformError renders the single generic rejection page. Every blocked
// request looks identical regardless of the stage that rejected it.
func uniformError(w http.ResponseWriter, status int) {
	if status == 0 {
		status = http.StatusForbidden
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Del("Content-Length")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Not available</title>
<style>:root{color-scheme:dark}body{margin:0;min-height:100vh;display:grid;place-items:center;
background:#0b0d10;color:#8b93a3;font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
div{text-align:center;padding:24px}h1{margin:0 0 8px;font-size:16px;font-weight:600;color:#c9d1de}</style>
</head><body><div><h1>Request not available</h1><p>The request could not be completed.</p></div></body></html>`)
}

// maintenancePage is shown when a proxy is in maintenance mode.
func maintenancePage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", "300")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = io.WriteString(w, `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Maintenance</title>
<style>:root{color-scheme:dark}body{margin:0;min-height:100vh;display:grid;place-items:center;
background:#0b0d10;color:#8b93a3;font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
div{text-align:center}h1{margin:0 0 8px;font-size:16px;color:#c9d1de}</style>
</head><body><div><h1>Down for maintenance</h1><p>Please check back shortly.</p></div></body></html>`)
}

func newRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// requestIDFor keeps a client-supplied ID when it is a plain token, so a trace
// can follow a request from an upstream load balancer; anything else is
// replaced rather than echoed into logs and headers.
func requestIDFor(r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get("X-Request-Id"))
	if id == "" || len(id) > 64 {
		return newRequestID()
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.'
		if !ok {
			return newRequestID()
		}
	}
	return id
}
