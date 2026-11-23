package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func selfSignedPEM(t *testing.T, names []string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func TestUploadCertStoresAnUploadedCertificate(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	certPEM, keyPEM := selfSignedPEM(t, []string{"upload.example.com", "www.upload.example.com"})

	body, _ := json.Marshal(map[string]string{"cert_pem": certPEM, "key_pem": keyPEM})
	req := httptest.NewRequest(http.MethodPost, "/api/certs/upload", strings.NewReader(string(body)))
	req.Host = "gui.local"
	req.RemoteAddr = "10.0.0.10:5000"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", rec.Code, rec.Body.String())
	}
	certs, err := st.ListCerts()
	if err != nil || len(certs) != 1 {
		t.Fatalf("list certs = %v, %v", certs, err)
	}
	c := certs[0]
	if c.Source != "uploaded" || c.Status != "issued" {
		t.Fatalf("stored source=%q status=%q", c.Source, c.Status)
	}
	if c.Domains != "upload.example.com,www.upload.example.com" {
		t.Fatalf("domains = %q", c.Domains)
	}
}

func TestUploadCertRejectsMismatchedKey(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	certPEM, _ := selfSignedPEM(t, []string{"upload.example.com"})
	_, otherKey := selfSignedPEM(t, []string{"other.example.com"})

	body := fmt.Sprintf(`{"cert_pem":%q,"key_pem":%q}`, certPEM, otherKey)
	req := httptest.NewRequest(http.MethodPost, "/api/certs/upload", strings.NewReader(body))
	req.Host = "gui.local"
	req.RemoteAddr = "10.0.0.10:5000"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mismatched key = %d: %s", rec.Code, rec.Body.String())
	}
}
