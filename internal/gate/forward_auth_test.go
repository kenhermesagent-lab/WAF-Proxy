package gate

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// newForwardAuthGate returns a gate with one provider and a proxy that uses it.
func newForwardAuthGate(t *testing.T, loginURL, secret string) (*Gate, *model.Proxy) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	box, err := wfcrypto.New(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.Seal(secret)
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.CreateAuthProvider(&model.AuthProvider{
		Name: "test", Kind: "authelia", VerifyURL: "http://provider.invalid/api/verify",
		LoginURL: loginURL, Header: "X-Wafproxy-Auth", Secret: sealed,
	})
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{st: st, box: box, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return g, &model.Proxy{ID: 1, Hostname: "app.example.com", GateMode: "forward_auth", AuthProviderID: &id}
}

// pointProvider moves the stored provider's verify URL onto the test server.
func pointProvider(t *testing.T, g *Gate, p *model.Proxy, url string) {
	t.Helper()
	prov, err := g.st.GetAuthProvider(*p.AuthProviderID)
	if err != nil {
		t.Fatal(err)
	}
	prov.VerifyURL = url
	if err := g.st.UpdateAuthProvider(prov); err != nil {
		t.Fatal(err)
	}
}

func request(g *Gate, p *model.Proxy, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Host = p.Hostname
	rec := httptest.NewRecorder()
	g.Handle(rec, r, p, netip.MustParseAddr("203.0.113.9"))
	return rec
}

func TestForwardAuthAllowsAValidSession(t *testing.T) {
	var seenURL, seenSecret, seenMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenURL = r.Header.Get("X-Original-URL")
		seenSecret = r.Header.Get("X-Wafproxy-Auth")
		seenMethod = r.Header.Get("X-Forwarded-Method")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	g, p := newForwardAuthGate(t, "", "s3cret")
	pointProvider(t, g, p, srv.URL)

	r := httptest.NewRequest(http.MethodGet, "/private?x=1", nil)
	r.Host = p.Hostname
	if g.Handle(httptest.NewRecorder(), r, p, netip.MustParseAddr("203.0.113.9")) {
		t.Fatal("an authenticated request was still handled by the gate")
	}
	if seenURL != "http://app.example.com/private?x=1" {
		t.Fatalf("X-Original-URL = %q", seenURL)
	}
	if seenSecret != "s3cret" {
		t.Fatalf("shared secret header = %q", seenSecret)
	}
	if seenMethod != http.MethodGet {
		t.Fatalf("X-Forwarded-Method = %q", seenMethod)
	}
}

func TestForwardAuthSendsAnUnauthenticatedVisitorToThePortal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	g, p := newForwardAuthGate(t, "https://auth.example.com", "")
	pointProvider(t, g, p, srv.URL)

	rec := request(g, p, "/private")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://auth.example.com?rd=http%3A%2F%2Fapp.example.com%2Fprivate" {
		t.Fatalf("Location = %q", loc)
	}
}

func TestForwardAuthPassesAProviderRedirectThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/api/redirect?rd=x")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	g, p := newForwardAuthGate(t, "", "")
	pointProvider(t, g, p, srv.URL)

	rec := request(g, p, "/private")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != srv.URL+"/api/redirect?rd=x" {
		t.Fatalf("provider redirect was not resolved against the provider: %q", loc)
	}
}

func TestForwardAuthFailsClosedWhenTheProviderIsDown(t *testing.T) {
	g, p := newForwardAuthGate(t, "", "")
	rec := request(g, p, "/private")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("provider.invalid")) {
		t.Fatalf("the deny page leaked the provider URL: %q", rec.Body.String())
	}
}

func TestForwardAuthWithoutAProviderRefuses(t *testing.T) {
	g, _ := newForwardAuthGate(t, "", "")
	p := &model.Proxy{ID: 2, Hostname: "app.example.com", GateMode: "forward_auth"}
	if rec := request(g, p, "/private"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}
