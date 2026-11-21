package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// TestListCertsExposesProviderChoices guards the data behind the "DNS provider"
// dropdown: an empty or missing provider list leaves the console with a select
// that cannot do anything.
func TestListCertsExposesProviderChoices(t *testing.T) {
	srv, st, token, _ := newObservabilityServer(t)

	get := func() struct {
		Certs      []map[string]any `json:"certs"`
		Providers  []string         `json:"providers"`
		Configured []string         `json:"configured"`
	} {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/certs", nil)
		req.Host = "gui.local"
		req.RemoteAddr = "192.168.101.10:5000"
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/certs = %d: %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Certs      []map[string]any `json:"certs"`
			Providers  []string         `json:"providers"`
			Configured []string         `json:"configured"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode %q: %v", rec.Body.String(), err)
		}
		return out
	}

	body := get()
	if len(body.Providers) == 0 {
		t.Fatal("the provider list is empty, so the DNS provider dropdown has no options")
	}
	for _, want := range []string{"duckdns", "cloudflare", "rfc2136"} {
		found := false
		for _, p := range body.Providers {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("provider %q missing from %v", want, body.Providers)
		}
	}
	if body.Configured == nil {
		t.Fatal("configured must be an array, not null")
	}
	if len(body.Configured) != 0 {
		t.Fatalf("fresh install reports stored credentials: %v", body.Configured)
	}

	// Credentials saved by the setup wizard or an earlier request tell the
	// console that the provider can be used without retyping them.
	if err := st.UpsertDNSCredential("duckdns", "DuckDNS", "sealed"); err != nil {
		t.Fatal(err)
	}
	body = get()
	if len(body.Configured) != 1 || body.Configured[0] != "duckdns" {
		t.Fatalf("configured = %v, want [duckdns]", body.Configured)
	}
}

func TestUpdateCertRenewMode(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	id, err := st.SaveCert(&model.Cert{Domains: "example.com", Provider: "duckdns", Status: "pending"})
	if err != nil {
		t.Fatal(err)
	}
	idText := strconv.FormatInt(id, 10)

	put := func(certID, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/api/certs/"+certID, strings.NewReader(body))
		req.Host = "gui.local"
		req.RemoteAddr = "192.168.101.10:5000"
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		req.Header.Set("X-CSRF-Token", csrf)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	rec := put(idText, `{"renew_mode":"monthly"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/certs/%s = %d: %s", idText, rec.Code, rec.Body.String())
	}
	cert, err := st.GetCert(id)
	if err != nil {
		t.Fatal(err)
	}
	if cert.RenewMode != model.CertRenewMonthly {
		t.Fatalf("renew_mode = %q, want %q", cert.RenewMode, model.CertRenewMonthly)
	}

	if rec := put(idText, `{"renew_mode":"yearly"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid mode = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if rec := put("999", `{"renew_mode":"monthly"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("missing cert = %d, want 404: %s", rec.Code, rec.Body.String())
	}
}

// TestCreateCertRejectsMissingProvider guards the case the certificate modal
// used to submit: an empty or unknown provider must never reach the background
// issuance path, where it would fail asynchronously and look like a broken DNS
// provider.
func TestCreateCertRejectsMissingProvider(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)

	post := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/certs", strings.NewReader(body))
		req.Host = "gui.local"
		req.RemoteAddr = "192.168.101.10:5000"
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		req.Header.Set("X-CSRF-Token", csrf)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	for name, body := range map[string]string{
		"missing provider": `{"domains":"example.com"}`,
		"empty provider":   `{"domains":"example.com","provider":""}`,
		"unknown provider": `{"domains":"example.com","provider":"not-a-provider"}`,
		"missing domains":  `{"provider":"duckdns"}`,
	} {
		rec := post(body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400: %s", name, rec.Code, rec.Body.String())
		}
	}
}
