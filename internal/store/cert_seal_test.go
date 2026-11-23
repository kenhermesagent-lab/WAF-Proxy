package store

import (
	"bytes"
	"testing"

	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func testBox(t *testing.T) *wfcrypto.Box {
	t.Helper()
	box, err := wfcrypto.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return box
}

const testPrivateKey = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n"

func TestSaveCertSealsPrivateKey(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.SetSecretBox(testBox(t))

	id, err := st.SaveCert(&model.Cert{Domains: "example.test", Provider: "uploaded", Status: "issued", CertPEM: []byte("CERT"), KeyPEM: []byte(testPrivateKey)})
	if err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := st.db.QueryRow(`SELECT key_pem FROM certificates WHERE id = ?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("PRIVATE KEY")) {
		t.Fatalf("private key stored in plaintext: %q", stored)
	}
	if !bytes.HasPrefix(stored, []byte(sealedPrefix)) {
		t.Fatalf("stored key has no seal prefix: %q", stored)
	}
	got, err := st.GetCert(id)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.KeyPEM) != testPrivateKey {
		t.Fatalf("GetCert key = %q, want the original", got.KeyPEM)
	}
}

func TestSealStoredCertKeysMigratesPlaintext(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// A row written by a release that stored the PEM as-is.
	res, err := st.db.Exec(`INSERT INTO certificates(domains, provider, status, cert_pem, key_pem, created_at, source, site_id)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, "legacy.test", "uploaded", "issued", "CERT", testPrivateKey, "2026-01-01T00:00:00Z", "uploaded", st.SiteID())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()

	st.SetSecretBox(testBox(t))
	n, err := st.SealStoredCertKeys()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("sealed %d rows, want 1", n)
	}
	if again, err := st.SealStoredCertKeys(); err != nil || again != 0 {
		t.Fatalf("second pass = %d, %v; want 0, nil", again, err)
	}
	got, err := st.GetCert(id)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.KeyPEM) != testPrivateKey {
		t.Fatalf("GetCert key = %q, want the original", got.KeyPEM)
	}
}

func TestSealedKeyNeedsTheMasterKey(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.SetSecretBox(testBox(t))
	id, err := st.SaveCert(&model.Cert{Domains: "sealed.test", Status: "issued", CertPEM: []byte("CERT"), KeyPEM: []byte(testPrivateKey)})
	if err != nil {
		t.Fatal(err)
	}
	st.Close()

	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.GetCert(id); err == nil {
		t.Fatal("reading a sealed key without a master key succeeded")
	}
}
