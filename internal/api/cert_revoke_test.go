package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestRevokeCertDeletesAnUploadedCertificate(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	certPEM, keyPEM := selfSignedPEM(t, []string{"revoke.example.com"})
	body, _ := json.Marshal(map[string]string{"cert_pem": certPEM, "key_pem": keyPEM})
	req := httptest.NewRequest(http.MethodPost, "/api/certs/upload", strings.NewReader(string(body)))
	req.Host = "gui.local"
	req.RemoteAddr = "10.0.0.10:5000"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", rec.Code, rec.Body.String())
	}
	certs, err := st.ListCerts()
	if err != nil || len(certs) != 1 {
		t.Fatalf("list certs = %v, %v", certs, err)
	}

	path := "/api/certs/" + strconv.FormatInt(certs[0].ID, 10) + "/revoke"
	req = httptest.NewRequest(http.MethodPost, path, nil)
	req.Host = "gui.local"
	req.RemoteAddr = "10.0.0.10:5000"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	req.Header.Set("X-CSRF-Token", csrf)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d: %s", rec.Code, rec.Body.String())
	}
	if certs, err := st.ListCerts(); err != nil || len(certs) != 0 {
		t.Fatalf("certificate survived revocation: %v, %v", certs, err)
	}
}
