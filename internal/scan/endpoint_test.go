package scan

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func TestPublishedBaseDialsTheListener(t *testing.T) {
	cases := map[string]string{
		":8443":          "https://127.0.0.1:8443",
		"0.0.0.0:8443":   "https://127.0.0.1:8443",
		"127.0.0.1:9443": "https://127.0.0.1:9443",
		"[::]:8443":      "https://[::1]:8443",
		"192.0.2.10:443": "https://192.0.2.10:443",
		"":               "https://127.0.0.1:443",
	}
	for listen, want := range cases {
		if got := PublishedBase(listen); got != want {
			t.Errorf("PublishedBase(%q) = %q, want %q", listen, got, want)
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
