// Package internalca issues certificates from a local root for installs that
// have no public domain.
package internalca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Authority is a local root and the material needed to issue from it.
type Authority struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

// Load opens the root in dir, creating it on first use. The key is written
// 0600 and never leaves the data directory.
func Load(dir string) (*Authority, error) {
	if dir == "" {
		return nil, errors.New("no data directory for the internal CA")
	}
	certPath := filepath.Join(dir, "internal-ca.pem")
	keyPath := filepath.Join(dir, "internal-ca-key.pem")
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		return parse(certPEM, keyPEM)
	}
	if certErr == nil || keyErr == nil {
		return nil, errors.New("the internal CA has a certificate but no key")
	}
	if !os.IsNotExist(certErr) || !os.IsNotExist(keyErr) {
		return nil, fmt.Errorf("read internal CA: %v / %v", certErr, keyErr)
	}
	auth, err := generate()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(auth.key)
	if err != nil {
		return nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, auth.certPEM, 0o644); err != nil {
		return nil, err
	}
	return auth, nil
}

func generate() (*Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "WAF-Proxy Internal CA", Organization: []string{"WAF-Proxy"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Authority{cert: cert, key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

func parse(certPEM, keyPEM []byte) (*Authority, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("the internal CA certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("the internal CA key is not PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return &Authority{cert: cert, key: key, certPEM: certPEM}, nil
}

// RootPEM returns the trust anchor an operator installs on client devices.
func (a *Authority) RootPEM() []byte { return a.certPEM }

// RootsFor is the trust store a listener certificate this CA signed verifies
// against: the system's own store plus the root in dir, so a site with a public
// certificate still verifies. It reads only the root, creates nothing, and
// returns nil when this install never issued from the internal CA.
func RootsFor(dir string) *x509.CertPool {
	if dir == "" {
		return nil
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, "internal-ca.pem"))
	if err != nil {
		return nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(certPEM) {
		return nil
	}
	return pool
}

// Issue signs a leaf for the given hostnames. Wildcards are allowed in the
// leftmost label only, which is what home installs need.
func (a *Authority) Issue(hosts []string) (certPEM, keyPEM []byte, notBefore, notAfter time.Time, err error) {
	if len(hosts) == 0 {
		return nil, nil, time.Time{}, time.Time{}, errors.New("no hostnames to issue for")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, err
	}
	now := time.Now()
	notBefore, notAfter = now.Add(-time.Hour), now.AddDate(0, 0, 90)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0]},
		DNSNames:     hosts,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		notBefore, notAfter, nil
}
