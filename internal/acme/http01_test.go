package acme

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTP01ServesPresentedTokensOnly(t *testing.T) {
	c := NewHTTP01Challenge()
	if err := c.Present("host.home.arpa", "tok123", "tok123.keyauth"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/tok123", nil)
	rec := httptest.NewRecorder()
	c.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "tok123.keyauth" {
		t.Fatalf("token response = %d %q", rec.Code, rec.Body.String())
	}

	missing := httptest.NewRecorder()
	c.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/other", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("unknown token = %d", missing.Code)
	}

	_ = c.CleanUp("host.home.arpa", "tok123", "")
	cleaned := httptest.NewRecorder()
	c.ServeHTTP(cleaned, req)
	if cleaned.Code != http.StatusNotFound {
		t.Fatalf("cleaned token still served: %d", cleaned.Code)
	}
}
