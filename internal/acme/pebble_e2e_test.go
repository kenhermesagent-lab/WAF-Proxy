package acme

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/proxy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// TestPebbleHTTP01 runs real issuance against Pebble. It is opt-in because it
// needs the Pebble process listening on httpPort 5002:
//
//	PEBBLE_DIRECTORY=https://localhost:14000/dir PEBBLE_CA=<pebble.minica.pem> go test ./internal/acme -run Pebble -v
func TestPebbleHTTP01(t *testing.T) {
	directory, ca := os.Getenv("PEBBLE_DIRECTORY"), os.Getenv("PEBBLE_CA")
	if directory == "" || ca == "" {
		t.Skip("set PEBBLE_DIRECTORY and PEBBLE_CA to run against Pebble")
	}
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	box, err := wfcrypto.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	m := New(st, box, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.SetDirectory(directory, ca)
	m.now = time.Now

	srv := &http.Server{Handler: proxy.PlainHTTPHandler(m.HTTP01()), ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", ":5002")
	if err != nil {
		t.Fatalf("listen :5002: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Shutdown(context.Background())

	issue := func(domain string) (int64, error) {
		expires := time.Now().Add(time.Hour)
		id, err := st.SaveCert(&model.Cert{Domains: domain, Challenge: model.CertChallengeHTTP,
			Status: "pending", ExpiresAt: &expires, Source: model.CertSourceACME})
		if err != nil {
			t.Fatal(err)
		}
		return id, m.Issue(id)
	}

	id, err := issue("localhost")
	if err != nil {
		t.Fatalf("HTTP-01 issuance through the listener: %v", err)
	}
	issued, err := st.GetCert(id)
	if err != nil || issued == nil || issued.Status != "issued" || len(issued.CertPEM) == 0 {
		t.Fatalf("stored certificate = %+v, err %v", issued, err)
	}
	if testing.Short() {
		return
	}

	// A name Pebble's VA cannot resolve must fail and leave the row in error.
	badID, err := issue("no-such-canary.invalid")
	if err == nil {
		t.Fatal("issuance for an unreachable name succeeded")
	}
	if failed, _ := st.GetCert(badID); failed == nil || failed.Status != "error" || failed.LastError == "" {
		t.Fatalf("failed certificate row = %+v", failed)
	}

	// The same listener redirects ordinary traffic to HTTPS.
	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/foo?x=1", nil)
	rec := httptest.NewRecorder()
	proxy.PlainHTTPHandler(m.HTTP01()).ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "https://gateway.local/foo?x=1" {
		t.Fatalf("redirect = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}
