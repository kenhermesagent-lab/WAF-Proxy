package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func TestCertificateForHostResolvesTheConsoleName(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "console.example.com"},
		DNSNames:     []string{"console.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	expires := tmpl.NotAfter
	if _, err := st.SaveCert(&model.Cert{
		Domains: "console.example.com", Status: "issued", ExpiresAt: &expires,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		Source:  model.CertSourceUploaded,
	}); err != nil {
		t.Fatal(err)
	}
	m := New(st, nil, slog.New(slog.DiscardHandler))
	if _, err := m.CertificateForHost("CONSOLE.example.com."); err != nil {
		t.Fatalf("console certificate: %v", err)
	}
	if _, err := m.CertificateForHost("other.example.com"); err == nil {
		t.Fatal("an unrelated name resolved a certificate")
	}
}
