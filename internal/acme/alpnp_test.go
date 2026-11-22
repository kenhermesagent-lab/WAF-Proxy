package acme

import "testing"

func TestALPNChallengeServesOnlyWhilePending(t *testing.T) {
	c := NewALPNChallenge()
	if _, ok := c.Certificate("app.example.com", []string{"acme-tls/1"}); ok {
		t.Fatal("no validation certificate should exist before Present")
	}
	if err := c.Present("App.Example.com", "token", "key-auth"); err != nil {
		t.Fatal(err)
	}
	cert, ok := c.Certificate("app.example.com", []string{"acme-tls/1"})
	if !ok || cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("pending validation certificate was not served")
	}
	if _, ok := c.Certificate("app.example.com", []string{"h2", "http/1.1"}); ok {
		t.Fatal("the validation certificate must only answer acme-tls/1")
	}
	if err := c.CleanUp("app.example.com", "token", "key-auth"); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Certificate("app.example.com", []string{"acme-tls/1"}); ok {
		t.Fatal("validation certificate survived CleanUp")
	}
}
