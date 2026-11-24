package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// freeUDPPort returns a free loopback UDP port. QUIC cannot share the TCP port
// a test listener holds, so each test picks its own.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// startHTTP3 enables h3 on the proxy, binds its WAN listener and waits until
// QUIC answers. The TCP listener binds 127.0.0.1 so the test owns both sockets.
func startHTTP3(t *testing.T, px *Server, port int) (*http.Client, *Listeners) {
	t.Helper()
	px.EnableHTTP3(port)
	lns, err := px.Listen(context.Background(), freeAddr(t))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = lns.Serve() }()
	t.Cleanup(func() { lns.Close() })

	// The SNI must be the site's hostname: the proxy only issues a certificate
	// for a hostname it serves, so dialing the loopback address by name would
	// fail in the certificate resolver rather than in the test.
	client := &http.Client{
		Transport: &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: testHost}},
		Timeout:   5 * time.Second,
	}
	waitHTTP3(t, client, port)
	return client, lns
}

// waitHTTP3 polls until the QUIC socket answers. The request carries no site
// hostname, so it takes the blackhole path and does not reach the upstream.
func waitHTTP3(t *testing.T, client *http.Client, port int) {
	t.Helper()
	url := "https://127.0.0.1:" + strconv.Itoa(port) + "/"
	deadline := time.Now().Add(5 * time.Second)
	var err error
	for time.Now().Before(deadline) {
		var resp *http.Response
		if resp, err = client.Get(url); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("http/3 did not answer on %d: %v", port, err)
}

// h3Request sends one request over QUIC with the site's hostname in Host, which
// is what the proxy routes on.
func h3Request(t *testing.T, client *http.Client, port int, method, path, body string) (*http.Response, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, "https://127.0.0.1:"+strconv.Itoa(port)+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = testHost
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s over h3: %v", method, path, err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(got)
}

// The h3 path is the same handler, so a request that works over HTTP/2 works
// here with the same status, body and upstream count.
func TestHTTP3ServesTheSamePipeline(t *testing.T) {
	h := newHarness(t)
	port := freeUDPPort(t)
	client, _ := startHTTP3(t, h.px, port)

	resp, body := h3Request(t, client, port, http.MethodGet, "/", "")
	if resp.ProtoMajor != 3 {
		t.Fatalf("protocol = %s, want HTTP/3", resp.Proto)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "upstream:/:") {
		t.Fatalf("upstream response missing: %q", body)
	}

	resp, body = h3Request(t, client, port, http.MethodHead, "/", "")
	if resp.StatusCode != http.StatusOK || body != "" {
		t.Fatalf("HEAD = %d %q, want 200 with no body", resp.StatusCode, body)
	}

	resp, _ = h3Request(t, client, port, http.MethodPost, "/", "a=1&b=2")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST status = %d, want 200", resp.StatusCode)
	}
	if got := h.hits.Load(); got != 3 {
		t.Fatalf("upstream hits = %d, want 3 (GET, HEAD and POST)", got)
	}
}

// A source the policy blocks is refused over h3 exactly as over TCP: nothing
// about the request is retried, rerouted or handed to the upstream.
func TestHTTP3BlockedByTheSamePolicy(t *testing.T) {
	h := newHarness(t)
	// The h3 client connects from loopback, so that is the source the policy
	// sees: the test's fake HTTP/1.1 address is not on the wire here.
	if _, err := h.st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyIPBlacklist, Value: "127.0.0.1", Action: "block", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.pol.Reload(); err != nil {
		t.Fatal(err)
	}
	port := freeUDPPort(t)
	client, _ := startHTTP3(t, h.px, port)

	resp, _ := h3Request(t, client, port, http.MethodGet, "/", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked status = %d, want 403", resp.StatusCode)
	}
	if h.hits.Load() != 0 {
		t.Fatalf("upstream hits = %d for a blocked source, want 0", h.hits.Load())
	}
}

// The response cache sits inside the handler, so a cacheable GET over h3 is
// served without a second upstream request.
func TestHTTP3ServesACacheHit(t *testing.T) {
	h := newHarness(t)
	port := freeUDPPort(t)
	client, _ := startHTTP3(t, h.px, port)

	first, firstBody := h3Request(t, client, port, http.MethodGet, "/cache", "")
	second, secondBody := h3Request(t, client, port, http.MethodGet, "/cache", "")
	if first.StatusCode != http.StatusOK || second.StatusCode != http.StatusOK {
		t.Fatalf("cache statuses = %d, %d", first.StatusCode, second.StatusCode)
	}
	if firstBody != secondBody {
		t.Fatalf("cache changed the body: %q vs %q", firstBody, secondBody)
	}
	if h.hits.Load() != 1 {
		t.Fatalf("upstream hits = %d after two cacheable GETs over h3, want 1", h.hits.Load())
	}
}

// Alt-Svc is the only thing that points a client at QUIC. It appears on a TLS
// response on HTTP/1.1 and HTTP/2, never when h3 is off, on a plain-HTTP
// request, or on an answer that already came over h3.
func TestAltSvcOnlyWhenHTTP3IsOn(t *testing.T) {
	h := newHarness(t)
	rec := h.request(http.MethodGet, testHost, "/", "", nil)
	if got := rec.Header().Get("Alt-Svc"); got != "" {
		t.Fatalf("Alt-Svc = %q with HTTP/3 off", got)
	}

	h.px.EnableHTTP3(8443)
	rec = h.request(http.MethodGet, testHost, "/", "", nil)
	if got, want := rec.Header().Get("Alt-Svc"), `h3=":8443"; ma=86400`; got != want {
		t.Fatalf("Alt-Svc = %q, want %q", got, want)
	}

	// The plain-HTTP redirector cannot serve h3, so it must not advertise it.
	plain := httptest.NewRequest(http.MethodGet, "/", nil)
	plain.Host = testHost
	plainRec := httptest.NewRecorder()
	h.px.ServeHTTP(plainRec, plain)
	if got := plainRec.Header().Get("Alt-Svc"); got != "" {
		t.Fatalf("Alt-Svc = %q on a plain-HTTP request", got)
	}

	// A request that already arrived over h3 needs no alternative.
	over3 := httptest.NewRequest(http.MethodGet, "/", nil)
	over3.Host = testHost
	over3.TLS = &tls.ConnectionState{}
	over3.Proto, over3.ProtoMajor, over3.ProtoMinor = "HTTP/3.0", 3, 0
	rec3 := httptest.NewRecorder()
	h.px.ServeHTTP(rec3, over3)
	if got := rec3.Header().Get("Alt-Svc"); got != "" {
		t.Fatalf("Alt-Svc = %q on an HTTP/3 request", got)
	}
}

// With the flag off the TCP listener behaves as before and no UDP socket is
// held: the port the tests reserved is still bindable.
func TestHTTP3OffLeavesTheUDPPortFree(t *testing.T) {
	px, err := New(Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	port := freeUDPPort(t)
	lns, err := px.Listen(context.Background(), freeAddr(t))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = lns.Serve() }()
	defer lns.Close()

	pc, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("UDP port held with HTTP/3 off: %v", err)
	}
	_ = pc.Close()
}

// A UDP port taken by something else leaves HTTPS serving and stops the
// advertisement: a client must not be told to use an alternative that is not
// there.
func TestHTTP3BindFailureFallsBackToTCP(t *testing.T) {
	px, err := New(Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	held, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	px.EnableHTTP3(held.LocalAddr().(*net.UDPAddr).Port)

	addr := freeAddr(t)
	lns, err := px.Listen(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer lns.Close()
	go func() { _ = lns.Serve() }()
	if err := waitDial(addr); err != nil {
		t.Fatalf("tcp listener stopped when h3 could not bind: %v", err)
	}
	if got := px.http3Port(); got != 0 {
		t.Fatalf("http3 port still advertised as %d after a failed bind", got)
	}
}

// A demotion releases the UDP socket with the TCP one, so the peer promoting
// can bind immediately.
func TestHTTP3DrainReleasesTheUDPPort(t *testing.T) {
	h := newHarness(t)
	port := freeUDPPort(t)
	_, lns := startHTTP3(t, h.px, port)
	lns.DrainTimeout(time.Second)

	var err error
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var pc net.PacketConn
		if pc, err = net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(port)); err == nil {
			_ = pc.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("UDP port %d still held after drain: %v", port, err)
}

// The QUIC config is where the replay and flooding guarantees live: 0-RTT off,
// a bounded stream budget and a per-source handshake window.
func TestHTTP3RefusesZeroRTTAndBoundsStreams(t *testing.T) {
	px, err := New(Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	cfg := px.h3QUICConfig()
	if cfg.Allow0RTT {
		t.Fatal("0-RTT must stay off: a replayed request would skip the handshake")
	}
	if cfg.MaxIncomingStreams != h3MaxIncomingStreams {
		t.Fatalf("MaxIncomingStreams = %d, want %d", cfg.MaxIncomingStreams, h3MaxIncomingStreams)
	}
	if cfg.GetConfigForClient == nil {
		t.Fatal("no handshake limiter installed")
	}
}

func TestH3HandshakeWindowRefusesAFlood(t *testing.T) {
	var a h3Attempts
	first := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 1000}
	for i := 0; i < h3HandshakeBurst; i++ {
		if !a.allow(first) {
			t.Fatalf("attempt %d refused inside the burst", i+1)
		}
	}
	if a.allow(first) {
		t.Fatal("the burst was not bounded")
	}
	other := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1000}
	if !a.allow(other) {
		t.Fatal("one source's window refused another source")
	}
}
