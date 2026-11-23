package internalca

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestIssueChainsToTheRootAndPersists(t *testing.T) {
	dir := t.TempDir()
	auth, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _, _, err := auth.Issue([]string{"nextcloud.home.arpa", "*.home.arpa"})
	if err != nil {
		t.Fatal(err)
	}
	if len(keyPEM) == 0 {
		t.Fatal("no private key issued")
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("leaf is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(auth.RootPEM()) {
		t.Fatal("root is not a usable PEM certificate")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "nextcloud.home.arpa"}); err != nil {
		t.Fatalf("leaf does not verify against the root: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "anything.home.arpa"}); err != nil {
		t.Fatalf("wildcard leaf does not cover a home.arpa name: %v", err)
	}

	// A second Load must reuse the same root, or installed trust anchors stop
	// matching after a restart.
	again, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(again.RootPEM()) != string(auth.RootPEM()) {
		t.Fatal("the root changed across loads")
	}
	info, err := os.Stat(filepath.Join(dir, "internal-ca-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("root key mode = %o, want 600", info.Mode().Perm())
	}
}

func TestIssueRefusesWithoutHostnames(t *testing.T) {
	auth, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := auth.Issue(nil); err == nil {
		t.Fatal("issued a certificate for no hostname")
	}
}
