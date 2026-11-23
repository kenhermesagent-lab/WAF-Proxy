package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPlainHTTPRedirectsAndServesChallenges(t *testing.T) {
	s := &Server{d: Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/path?q=1", nil)
	s.servePlainHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "https://app.example.com/path?q=1" {
		t.Fatalf("redirect = %d %q", rec.Code, rec.Header().Get("Location"))
	}

	s.SetHTTPChallengeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("token"))
	}))
	rec = httptest.NewRecorder()
	s.servePlainHTTP(rec, httptest.NewRequest(http.MethodGet, "http://app.example.com/.well-known/acme-challenge/t", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "token" {
		t.Fatalf("challenge = %d %q", rec.Code, rec.Body.String())
	}
}
