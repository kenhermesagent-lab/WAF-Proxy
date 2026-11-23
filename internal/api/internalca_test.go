package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIssueInternalCertificateAndServeRoot(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	body := `{"domains":["nextcloud.home.arpa","*.home.arpa"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/certs/internal", strings.NewReader(body))
	req.Host = "gui.local"
	req.RemoteAddr = "10.0.0.10:5000"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("internal issue = %d: %s", rec.Code, rec.Body.String())
	}
	certs, err := st.ListCerts()
	if err != nil || len(certs) != 1 {
		t.Fatalf("certs = %v, %v", certs, err)
	}
	if certs[0].Source != "internal" || certs[0].Status != "issued" {
		t.Fatalf("source=%q status=%q", certs[0].Source, certs[0].Status)
	}

	rootReq := httptest.NewRequest(http.MethodGet, "/api/certs/internal/root", nil)
	rootReq.Host = "gui.local"
	rootReq.RemoteAddr = "10.0.0.10:5000"
	rootReq.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	rootRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rootRec, rootReq)
	if rootRec.Code != http.StatusOK || !strings.Contains(rootRec.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("root = %d: %s", rootRec.Code, rootRec.Body.String())
	}
}

func TestInternalCertRejectsInvalidDomain(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/certs/internal", strings.NewReader(`{"domains":["bad host!"]}`))
	req.Host = "gui.local"
	req.RemoteAddr = "10.0.0.10:5000"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid domain = %d: %s", rec.Code, rec.Body.String())
	}
}
