package scantrust

import "testing"

// A token is valid only while its run holds it.
func TestTokensLiveForTheirRun(t *testing.T) {
	r := New()
	token, err := r.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 64 {
		t.Fatalf("token %q is not 32 random bytes in hex", token)
	}
	if !r.Valid(token) {
		t.Fatal("a fresh token is not valid")
	}
	if r.Valid("anything-else") {
		t.Fatal("an unknown token was accepted")
	}
	r.End(token)
	if r.Valid(token) {
		t.Fatal("a retired token still grants the exemption")
	}

	second, err := r.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if second == token {
		t.Fatal("two runs were given the same token")
	}
}
