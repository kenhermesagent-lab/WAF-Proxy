package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/botguard"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/gate"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/policy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

const (
	testIP   = "203.0.113.9"
	testHost = "app.example.com"
)

type harness struct {
	px     *Server
	st     *store.Store
	bans   *ban.Engine
	pol    *policy.Engine
	box    *wfcrypto.Box
	proxy  model.Proxy
	up     *httptest.Server
	hits   *atomic.Int32
	cancel context.CancelFunc
}

func newHarness(t testing.TB) *harness {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	box, err := wfcrypto.New(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	bans, err := ban.New(st, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	geo := geoip.Open(t.TempDir())
	profiles, err := st.ListProfiles()
	if err != nil {
		t.Fatal(err)
	}
	wafs := waf.NewSet(profiles, log)
	pol, err := policy.New(st, bans, nil, geo, wafs, log)
	if err != nil {
		t.Fatal(err)
	}

	hits := &atomic.Int32{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The health probe is not a client request and must not affect counts.
		if r.Header.Get("User-Agent") == "wafproxy-health/1.0" {
			w.WriteHeader(http.StatusOK)
			return
		}
		hits.Add(1)
		switch r.URL.Path {
		case "/slow":
			// Holds its budget slot long enough for a burst to overlap it.
			time.Sleep(500 * time.Millisecond)
			_, _ = fmt.Fprintf(w, "upstream:%s:", r.URL.Path)
			return
		case "/large":
			// A declared length above a profile's ceiling must be refused before
			// the body starts, not streamed and cut.
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", "200000")
			_, _ = w.Write(make([]byte, 200000))
			return
		case "/leak":
			// A leaky error page the CRS response rules must catch.
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, "<html><body>You have an error in your SQL syntax; check the manual</body></html>")
			return
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: You have an error in your SQL syntax\n\n")
			return
		case "/gzip":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			_, _ = io.WriteString(gz, "<html><body>You have an error in your SQL syntax</body></html>")
			_ = gz.Close()
			return
		case "/gzip-if-asked":
			// Compresses only when asked, the way an ordinary origin behaves.
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "max-age=60")
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				_, _ = io.WriteString(w, "compressed-page-payload")
				return
			}
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			_, _ = io.WriteString(gz, "compressed-page-payload")
			_ = gz.Close()
			return
		case "/always-gzip":
			// Ignores what it was asked for, so its body is never identity.
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "max-age=60")
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			_, _ = io.WriteString(gz, "always-encoded-payload")
			_ = gz.Close()
			return
		case "/trickle":
			// Flushed over several hundred milliseconds: longer than a body
			// deadline, to prove the deadline is the client's alone.
			w.Header().Set("Content-Type", "text/plain")
			for i := 0; i < 5; i++ {
				_, _ = fmt.Fprintf(w, "chunk-%d\n", i)
				w.(http.Flusher).Flush()
				time.Sleep(60 * time.Millisecond)
			}
			return
		case "/proto":
			// Echoes what the upstream was told about the client's scheme.
			_, _ = fmt.Fprintf(w, "proto:%s", r.Header.Get("X-Forwarded-Proto"))
			return
		case "/upload":
			// Echoes how many bytes arrived, so a streamed upload can be proven
			// whole without the harness holding it.
			n, _ := io.Copy(io.Discard, r.Body)
			_, _ = fmt.Fprintf(w, "size:%d", n)
			return
		case "/stream":
			// No length: the response is cut once it passes the ceiling.
			w.Header().Set("Content-Type", "text/plain")
			for i := 0; i < 8; i++ {
				_, _ = w.Write(make([]byte, 32*1024))
				w.(http.Flusher).Flush()
			}
			return
		}
		if r.URL.Path == "/ws" {
			conn, brw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n" +
				"Connection: Upgrade\r\n\r\nws-yo")
			_ = brw.Flush()
			_ = conn.Close()
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/cache" {
			w.Header().Set("Cache-Control", "max-age=60")
		}
		_, _ = fmt.Fprintf(w, "upstream:%s:%s", r.URL.Path, r.Header.Get("X-Forwarded-For"))
	}))

	p := model.Proxy{
		Hostname: testHost, Enabled: true, GateMode: "off", Fingerprint: "strict",
		BotLevel: "off", WAFMode: "off",
	}
	id, err := st.CreateProxy(&p)
	if err != nil {
		t.Fatal(err)
	}
	p.ID = id
	if err := st.ReplaceUpstreams(id, []model.Upstream{{ProxyID: id, URL: upstream.URL, Weight: 1, Enabled: true}}); err != nil {
		t.Fatal(err)
	}

	px, err := New(Deps{
		Store: st, Policy: pol, Gate: gate.New(st, box, bans, log), Bots: botguard.New(boxKey(), bans, st, log),
		Bans: bans, Geo: geo, Metrics: metrics.New("", ""), Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := px.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	evCtx, cancel := context.WithCancel(context.Background())
	go px.eventWriter(evCtx)

	h := &harness{px: px, st: st, bans: bans, pol: pol, box: box, proxy: p, up: upstream, hits: hits, cancel: cancel}
	t.Cleanup(func() {
		cancel()
		upstream.Close()
		px.mu.Lock()
		for _, e := range px.edges {
			if e.cancel != nil {
				e.cancel()
			}
		}
		px.mu.Unlock()
		_ = st.Close()
	})
	return h
}

func boxKey() []byte { return bytes.Repeat([]byte{0x42}, 32) }

func (h *harness) request(method, host, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	return h.requestFrom(testIP, method, host, path, body, hdr)
}

func (h *harness) requestFrom(src, method, host, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Host = host
	req.URL.Scheme = "https"
	req.URL.Host = host
	req.TLS = &tls.ConnectionState{}
	req.RemoteAddr = src + ":43210"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	h.px.ServeHTTP(rec, req)
	return rec
}

func (h *harness) waitEvent(t *testing.T, match func(model.Event) bool) model.Event {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		events, _, err := h.st.QueryEvents(store.EventFilter{From: time.Now().Add(-time.Hour), Limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if match(e) {
				return e
			}
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("expected event was not recorded")
	return model.Event{}
}

func TestPipelineAllowsAndRecords(t *testing.T) {
	h := newHarness(t)
	rec := h.request(http.MethodGet, testHost, "/", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "upstream:/:") {
		t.Fatalf("upstream response missing: %q", rec.Body.String())
	}
	if h.hits.Load() != 1 {
		t.Fatalf("upstream hits = %d, want 1", h.hits.Load())
	}
	e := h.waitEvent(t, func(e model.Event) bool { return e.Stage == "route" })
	if e.Action != "allow" || e.Status != http.StatusOK {
		t.Fatalf("event = %+v, want allow/200", e)
	}
}

func TestPipelineDecoyPathBans(t *testing.T) {
	h := newHarness(t)
	if _, err := h.st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyDecoy, Value: "/.env", Action: "block", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.pol.Reload(); err != nil {
		t.Fatal(err)
	}
	rec := h.request(http.MethodGet, testHost, "/.env", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	h.waitEvent(t, func(e model.Event) bool { return e.Stage == "decoy" && e.Action == "ban" })
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rec, ok := h.bans.Match(netip.MustParseAddr(testIP)); ok && rec.Permanent {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("decoy path did not create a permanent ban")
}

func TestPipelineTemporaryBan(t *testing.T) {
	h := newHarness(t)
	if _, err := h.bans.Add(testIP, "port scan", "manual", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	rec := h.request(http.MethodGet, testHost, "/", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	h.waitEvent(t, func(e model.Event) bool { return e.Stage == "temp-ban" })
	if h.hits.Load() != 0 {
		t.Fatalf("banned request reached the upstream")
	}
}

func TestPipelineUnknownHostBlackholes(t *testing.T) {
	h := newHarness(t)
	rec := h.request(http.MethodGet, "scanner.example.com", "/", "", nil)
	// httptest.ResponseRecorder cannot be hijacked, so the fallback status is
	// used. A real TCP connection is closed instead.
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMisdirectedRequest)
	}
	h.waitEvent(t, func(e model.Event) bool { return e.Stage == "unknown-host" })
}

// The follow-up review's Host probe (R2-19) put a SQL injection in the Host
// header. It names no configured site, so the site lookup refuses it before the
// WAF runs and it never reaches an upstream.
func TestPipelineHostHeaderInjectionIsRefused(t *testing.T) {
	h := newHarness(t)
	rec := h.request(http.MethodGet, testHost+`' OR 1=1--`, "/", "", nil)
	// httptest.ResponseRecorder cannot be hijacked, so the fallback status is
	// used. A real TCP connection is closed without an answer instead.
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMisdirectedRequest)
	}
	if h.hits.Load() != 0 {
		t.Fatalf("the injected Host reached the upstream %d time(s)", h.hits.Load())
	}
	e := h.waitEvent(t, func(e model.Event) bool { return e.Stage == "unknown-host" })
	if e.Action != "block" || e.Status != http.StatusMisdirectedRequest {
		t.Fatalf("event = %+v, want block/%d", e, http.StatusMisdirectedRequest)
	}
}

func TestPipelineDecoyHostBans(t *testing.T) {
	h := newHarness(t)
	if err := h.st.SetSetting("decoy_hosts", "admin.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := h.pol.Reload(); err != nil {
		t.Fatal(err)
	}
	// An address already on a temporary ban must be upgraded, not skipped: a
	// decoy hostname is proof of scanning, so the ban has to become permanent.
	if _, err := h.bans.Add(testIP, "rate limit", "manual", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	rec := h.request(http.MethodGet, "admin.example.com", "/", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	h.waitEvent(t, func(e model.Event) bool { return e.Stage == "decoy-host" && e.Action == "ban" })
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rec, ok := h.bans.Match(netip.MustParseAddr(testIP)); ok && rec.Permanent && rec.ExpiresAt == nil {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("decoy host did not upgrade the temporary ban to permanent")
}

func TestPipelineAccessGate(t *testing.T) {
	h := newHarness(t)
	sealed, err := h.box.Seal("letmein")
	if err != nil {
		t.Fatal(err)
	}
	p, err := h.st.GetProxy(h.proxy.ID)
	if err != nil {
		t.Fatal(err)
	}
	p.GateMode = "passphrase"
	p.GateSecret = sealed
	if err := h.st.UpdateProxy(p); err != nil {
		t.Fatal(err)
	}
	if err := h.px.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	rec := h.request(http.MethodGet, testHost, "/private", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Authentication required") {
		t.Fatalf("gate page = %d %q", rec.Code, rec.Body.String())
	}
	if h.hits.Load() != 0 {
		t.Fatalf("gated request reached the upstream")
	}

	bad := h.request(http.MethodPost, testHost, gate.LoginPath, "password=wrong&next=/private", nil)
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("bad login status = %d, want 401", bad.Code)
	}

	good := h.request(http.MethodPost, testHost, gate.LoginPath, "password=letmein&next=/private", nil)
	if good.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d, want 303", good.Code)
	}
	cookies := good.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login did not set a gate cookie")
	}
	cookie := cookies[0]
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Host = testHost
	req.URL.Scheme = "https"
	req.URL.Host = testHost
	req.TLS = &tls.ConnectionState{}
	req.RemoteAddr = testIP + ":43210"
	req.AddCookie(cookie)
	authed := httptest.NewRecorder()
	h.px.ServeHTTP(authed, req)
	if authed.Code != http.StatusOK || !strings.Contains(authed.Body.String(), "upstream:/private") {
		t.Fatalf("authed request = %d %q", authed.Code, authed.Body.String())
	}
}

func TestPipelineCachesCacheableGET(t *testing.T) {
	h := newHarness(t)
	first := h.request(http.MethodGet, testHost, "/cache", "", nil)
	second := h.request(http.MethodGet, testHost, "/cache", "", nil)
	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("statuses = %d, %d", first.Code, second.Code)
	}
	if first.Body.String() != second.Body.String() {
		t.Fatalf("cache changed the body: %q vs %q", first.Body.String(), second.Body.String())
	}
	if h.hits.Load() != 1 {
		t.Fatalf("upstream hits = %d after two cacheable GETs, want 1", h.hits.Load())
	}
}

func TestPipelineStripsSpoofedForwarding(t *testing.T) {
	h := newHarness(t)
	rec := h.request(http.MethodGet, testHost, "/echo", "", map[string]string{
		"X-Forwarded-For": "1.2.3.4",
		"X-Real-Ip":       "1.2.3.4",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "upstream:/echo:"+testIP) {
		t.Fatalf("spoofed forwarding header survived: %q", rec.Body.String())
	}
}

func TestPipelineRejectsOversizedBody(t *testing.T) {
	h := newHarness(t)
	h.px.SetBodyLimit(4096)
	rec := h.request(http.MethodPost, testHost, "/upload", strings.Repeat("a", 5000), nil)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if h.hits.Load() != 0 {
		t.Fatal("oversized body reached the upstream")
	}
	h.waitEvent(t, func(e model.Event) bool { return e.Stage == "body-limit" })
}

func TestPipelineWAFBlocksSQLi(t *testing.T) {
	h := newHarness(t)
	profiles, err := h.st.ListProfiles()
	if err != nil {
		t.Fatal(err)
	}
	var generic int64
	for _, p := range profiles {
		if p.Name == "Generic Web" {
			generic = p.ID
		}
	}
	if generic == 0 {
		t.Fatal("Generic Web profile missing")
	}
	p, _ := h.st.GetProxy(h.proxy.ID)
	p.WAFMode = "block"
	p.ProfileID = &generic
	if err := h.st.UpdateProxy(p); err != nil {
		t.Fatal(err)
	}
	if err := h.px.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec := h.request(http.MethodGet, testHost, "/search?q=1%27+OR+%271%27%3D%271", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("SQLi status = %d, want 403 (body %q)", rec.Code, rec.Body.String())
	}
	h.waitEvent(t, func(e model.Event) bool { return e.Stage == "waf" && e.Action == "block" })
	if h.hits.Load() != 0 {
		t.Fatal("SQLi request reached the upstream")
	}
}

// A detect-only verdict is logged and the request is forwarded. The event must
// keep the stage that produced the verdict instead of the forward's "route".
func TestLoggedVerdictKeepsItsStage(t *testing.T) {
	h := newHarness(t)
	profiles, err := h.st.ListProfiles()
	if err != nil {
		t.Fatal(err)
	}
	var generic int64
	for _, p := range profiles {
		if p.Name == "Generic Web" {
			generic = p.ID
		}
	}
	if generic == 0 {
		t.Fatal("Generic Web profile missing")
	}
	p, err := h.st.GetProxy(h.proxy.ID)
	if err != nil {
		t.Fatal(err)
	}
	p.WAFMode = "detect"
	p.ProfileID = &generic
	if err := h.st.UpdateProxy(p); err != nil {
		t.Fatal(err)
	}
	if err := h.px.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec := h.request(http.MethodGet, testHost, "/search?q=1%27+OR+%271%27%3D%271", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("detect-only request = %d, want 200", rec.Code)
	}
	e := h.waitEvent(t, func(e model.Event) bool { return e.Action == "log" })
	if e.Stage != "waf" {
		t.Fatalf("logged event stage = %q, want waf", e.Stage)
	}
}
