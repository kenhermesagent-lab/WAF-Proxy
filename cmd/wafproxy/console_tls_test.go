package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/acme"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func consoleCert(t *testing.T, serial int64, domain string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
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
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func TestConsoleTLSPicksUpAReplacementCertificate(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	expires := time.Now().Add(time.Hour)
	certPEM, keyPEM := consoleCert(t, 1, "console.example.com")
	id, err := st.SaveCert(&model.Cert{
		Domains: "console.example.com", Status: "issued", ExpiresAt: &expires,
		CertPEM: []byte(certPEM), KeyPEM: []byte(keyPEM), Source: model.CertSourceUploaded,
	})
	if err != nil {
		t.Fatal(err)
	}
	m := acme.New(st, nil, log)
	cfg, err := consoleTLSConfig(m, "console.example.com")
	if err != nil {
		t.Fatalf("console TLS config: %v", err)
	}
	serial := func() int64 {
		cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "console.example.com"})
		if err != nil {
			t.Fatalf("handshake certificate: %v", err)
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return leaf.SerialNumber.Int64()
	}
	if got := serial(); got != 1 {
		t.Fatalf("startup serial = %d, want 1", got)
	}

	// Replace the row the way a renewal does, then reload the cache.
	certPEM, keyPEM = consoleCert(t, 2, "console.example.com")
	if _, err := st.SaveCert(&model.Cert{
		ID: id, Domains: "console.example.com", Status: "issued", ExpiresAt: &expires,
		CertPEM: []byte(certPEM), KeyPEM: []byte(keyPEM), Source: model.CertSourceUploaded,
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	if got := serial(); got != 2 {
		t.Fatalf("serial after renewal = %d, want 2", got)
	}

	if _, err := consoleTLSConfig(m, "missing.example.com"); err == nil {
		t.Fatal("a host without a certificate passed the boot check")
	}
}
