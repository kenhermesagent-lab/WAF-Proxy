package backup

import (
	"strings"
	"testing"
)

func TestValidateRequiresEncryptionPassphrase(t *testing.T) {
	c := Config{Transport: "local", LocalDir: "/tmp/x", Keep: 7, Encrypt: true}
	if msg := c.Validate(); !strings.Contains(msg, "passphrase") {
		t.Fatalf("encrypt without a passphrase = %q", msg)
	}
	c.Passphrase = "too-short"
	if msg := c.Validate(); !strings.Contains(msg, "16") {
		t.Fatalf("short passphrase = %q", msg)
	}
	c.Passphrase = "a-16-character-passphrase"
	if msg := c.Validate(); msg != "" {
		t.Fatalf("valid encryption config = %q", msg)
	}
}

func TestEncryptRoundTrip(t *testing.T) {
	plain := []byte(`{"version":"1.0","proxies":[]}`)
	sealed, err := Encrypt("a-16-character-passphrase", plain)
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncrypted(sealed) || strings.Contains(string(sealed), "proxies") {
		t.Fatal("the encrypted backup is not sealed")
	}
	opened, err := Decrypt("a-16-character-passphrase", sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != string(plain) {
		t.Fatalf("decrypted %q, want %q", opened, plain)
	}
	if _, err := Decrypt("the-wrong-passphrase", sealed); err == nil {
		t.Fatal("a wrong passphrase opened the backup")
	}
	if IsEncrypted(plain) {
		t.Fatal("plain JSON was reported as encrypted")
	}
}
