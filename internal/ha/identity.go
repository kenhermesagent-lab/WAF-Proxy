package ha

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Identity is this node's TLS key pair for the HA link. It is self-signed: the
// pair is established by comparing one fingerprint, not by trusting a public CA.
type Identity struct {
	Cert tls.Certificate
	Leaf *x509.Certificate
	Node string
}

// LoadOrCreateIdentity loads data/ha/tls.{crt,key}, creating them on first use.
// It also ensures the role file carries a node id, because a certificate
// without an identity cannot be pinned.
func LoadOrCreateIdentity(dataDir string) (*Identity, error) {
	dir := RoleDir(dataDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	node, _ := Load(dataDir)
	if node.NodeID == "" {
		node.NodeID = randomID()
		node.Role = RoleStandby
		node.Epoch = 0
		if err := Save(dataDir, node); err != nil {
			return nil, err
		}
	}

	var cert tls.Certificate
	var err error
	if fileExists(certPath) && fileExists(keyPath) {
		cert, err = tls.LoadX509KeyPair(certPath, keyPath)
	} else {
		cert, err = newSelfSigned(node.NodeID)
		if err == nil {
			err = writeCertPair(certPath, keyPath, cert)
		}
	}
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	cert.Leaf = leaf
	return &Identity{Cert: cert, Leaf: leaf, Node: node.NodeID}, nil
}

// Fingerprint is the value an operator compares out of band: a digest of the
// public key, so renewing the certificate does not change it.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// ServerConfig serves the join endpoint. A client certificate is required but
// only pinned once a pair exists; before that the pairing code authenticates
// the request.
func (i *Identity) ServerConfig(pin string) *tls.Config {
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{i.Cert},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	if pin != "" {
		cfg.VerifyPeerCertificate = verifyPin(pin)
	}
	return cfg
}

// ClientConfig pins the peer's public key and refuses anything else.
func (i *Identity) ClientConfig(pin string) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{i.Cert},
		InsecureSkipVerify:    true, // replaced by the pin check below
		VerifyPeerCertificate: verifyPin(pin),
	}
}

func verifyPin(pin string) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("ha: peer sent no certificate")
		}
		cert, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return err
		}
		if Fingerprint(cert) != normalizeFingerprint(pin) {
			return fmt.Errorf("ha: peer fingerprint %s does not match the pinned %s", Fingerprint(cert), normalizeFingerprint(pin))
		}
		return nil
	}
}

func normalizeFingerprint(s string) string {
	out := ""
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			out += string(r)
		}
	}
	return lowerASCII(out)
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'F' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func newSelfSigned(nodeID string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "wafproxy-ha-" + nodeID},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func writeCertPair(certPath, keyPath string, cert tls.Certificate) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyDER, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyPEM, 0o600)
}

func randomID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return hex.EncodeToString(buf)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
