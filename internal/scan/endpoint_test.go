package scan

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func TestListenerBaseDialsTheBoundAddress(t *testing.T) {
	cases := map[string]string{
		":8443":          "https://127.0.0.1:8443",
		"0.0.0.0:8443":   "https://127.0.0.1:8443",
		"127.0.0.1:9443": "https://127.0.0.1:9443",
		"[::]:8443":      "https://[::1]:8443",
		"192.0.2.10:443": "https://192.0.2.10:443",
		"":               "https://127.0.0.1:443",
	}
	for listen, want := range cases {
		if got := ListenerBase(listen); got != want {
			t.Errorf("ListenerBase(%q) = %q, want %q", listen, got, want)
		}
	}
}

// The endpoint label is what a failed run shows: the address and port dialled,
// and the Host it claimed.
func TestEndpointLabelNamesTheDialAddressAndHost(t *testing.T) {
	u, _ := url.Parse("https://127.0.0.1:9443")
	ep := Endpoint{URL: u, Host: "app.example.com"}
	if got, want := ep.Label(), "https://127.0.0.1:9443 (Host: app.example.com)"; got != want {
		t.Fatalf("label = %q, want %q", got, want)
	}
}

// The hostname is the certificate name even though the dial address is the
// listener, so a valid certificate for the site is accepted.
func TestProbeClientUsesTheTLSName(t *testing.T) {
	tr, ok := probeClient(false, "app.example.com").Transport.(*http.Transport)
	if !ok {
		t.Fatal("probe client is not an http.Transport")
	}
	if got := tr.TLSClientConfig.ServerName; got != "app.example.com" {
		t.Fatalf("TLS server name = %q, want app.example.com", got)
	}
}

// Raw probes write their own TLS connection, so they must use the endpoint's
// certificate name rather than the Host header.
func TestRawProbeUsesTheEndpointTLSName(t *testing.T) {
	var mu sync.Mutex
	var sni string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		mu.Lock()
		sni = hello.ServerName
		mu.Unlock()
		return nil, nil
	}}
	srv.StartTLS()
	defer srv.Close()
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	u, _ := url.Parse(srv.URL)
	ep := Endpoint{URL: u, Host: "host-header.example.com", TLSName: "cert.example.com"}
	raw := "GET / HTTP/1.1\r\nHost: host-header.example.com\r\nConnection: close\r\n\r\n"
	if _, err := NewRunner(ep, ep, 0).sendRaw(context.Background(), raw); err == nil {
		t.Fatal("the untrusted listener certificate was accepted")
	}
	mu.Lock()
	got := sni
	mu.Unlock()
	if got != "cert.example.com" {
		t.Fatalf("TLS SNI = %q, want the endpoint's TLS name", got)
	}
}

// Only an unreachable endpoint triggers the listener fallback. A certificate
// error is not retried: the listener presents the same name and certificate.
func TestFallbackOnOnlyRetriesUnreachableEndpoints(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	tlsSrv.Config.ErrorLog = log.New(io.Discard, "", 0)
	defer tlsSrv.Close()
	if _, err := http.Get(tlsSrv.URL); err == nil {
		t.Fatal("an untrusted certificate was accepted")
	} else if fallbackOn(err) {
		t.Fatalf("a certificate error was treated as unreachable: %v", err)
	}
	if _, err := http.Get("http://127.0.0.1:1"); err == nil {
		t.Fatal("a closed port answered")
	} else if !fallbackOn(err) {
		t.Fatalf("a closed port did not trigger the fallback: %v", err)
	}
	if _, err := http.Get("http://scan-demo.invalid"); err == nil {
		t.Fatal("a reserved hostname resolved")
	} else if !fallbackOn(err) {
		t.Fatalf("a DNS failure did not trigger the fallback: %v", err)
	}
}

// A hostname that does not answer falls back to the node's listener with the
// hostname as Host, and every later probe uses that endpoint.
func TestPreflightFallsBackToTheListener(t *testing.T) {
	var fallbackHits atomic.Int64
	var sawHost atomic.Bool
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sawHost.CompareAndSwap(false, true) && r.Host != "app.example.com" {
			t.Errorf("fallback Host = %q, want app.example.com", r.Host)
		}
		fallbackHits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer fallback.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer up.Close()

	primary, _ := url.Parse("https://127.0.0.1:1")
	fb, _ := url.Parse(fallback.URL)
	upURL, _ := url.Parse(up.URL)
	target := Target{
		Proxy:    model.Proxy{Hostname: "app.example.com", Enabled: true},
		WAN:      Endpoint{URL: primary, Host: "app.example.com", TLSName: "app.example.com"},
		Fallback: Endpoint{URL: fb, Host: "app.example.com", TLSName: "app.example.com"},
		Upstream: Endpoint{URL: upURL, Host: "app.example.com"},
	}
	r := NewRunner(target.WAN, target.Upstream, 0)
	pf, err := r.RunPreflight(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if pf.Skip != "" {
		t.Fatalf("the listener fallback was skipped: %s", pf.Skip)
	}
	want := fallback.URL + " (Host: app.example.com)"
	if pf.Endpoint != want {
		t.Fatalf("endpoint = %q, want %q", pf.Endpoint, want)
	}
	if !strings.Contains(pf.Fallback, "https://127.0.0.1:1") || !strings.Contains(pf.Fallback, "did not answer") {
		t.Fatalf("fallback reason = %q, want the failed hostname and its error", pf.Fallback)
	}
	if r.wan.Label() != want {
		t.Fatalf("runner endpoint = %q, want the listener %q", r.wan.Label(), want)
	}

	if _, err := r.Run(context.Background(), []Probe{{
		Stage: StageWAF, Class: "test", Method: http.MethodGet, Path: "/",
	}}); err != nil {
		t.Fatal(err)
	}
	if fallbackHits.Load() == 0 {
		t.Fatal("a later probe did not use the fallback endpoint")
	}
}

// A preflight that cannot reach the listener records the endpoint it dialled
// and the transport error, instead of a bare "did not answer".
func TestPreflightNamesTheEndpointItCouldNotReach(t *testing.T) {
	wan, _ := url.Parse("https://127.0.0.1:1")
	up, _ := url.Parse("http://127.0.0.1:2")
	target := Target{
		Proxy:    model.Proxy{Hostname: "app.example.com", Enabled: true},
		WAN:      Endpoint{URL: wan, Host: "app.example.com", TLSName: "app.example.com"},
		Upstream: Endpoint{URL: up, Host: "app.example.com"},
	}
	pf, err := NewRunner(target.WAN, target.Upstream, 0).RunPreflight(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if pf.Skip == "" {
		t.Fatal("an unreachable listener did not skip the run")
	}
	for _, want := range []string{"https://127.0.0.1:1 (Host: app.example.com)", "did not answer"} {
		if !strings.Contains(pf.Skip, want) {
			t.Fatalf("skip = %q; want it to contain %q", pf.Skip, want)
		}
	}
}
