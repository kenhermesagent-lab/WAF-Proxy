package api

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMigrationNPMImportsLetEncryptCertificate(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t, []string{"live.example.com"})
	var bundle bytes.Buffer
	zw := zip.NewWriter(&bundle)
	for name, body := range map[string]string{"fullchain.pem": certPEM, "privkey.pem": keyPEM} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tokens":
			_, _ = w.Write([]byte(`{"token":"npm-token"}`))
		case "/api/nginx/proxy-hosts":
			_, _ = w.Write([]byte(`[{"domain_names":["live.example.com"],"forward_scheme":"http","forward_host":"10.1.1.5","forward_port":8081,"certificate_id":3,"ssl_forced":true}]`))
		case "/api/nginx/access-lists", "/api/nginx/redirection-hosts":
			_, _ = w.Write([]byte(`[]`))
		case "/api/nginx/certificates":
			_, _ = w.Write([]byte(`[{"id":3,"provider":"letsencrypt","nice_name":"live cert","domain_names":["live.example.com"],"expires_on":"2099-01-01T00:00:00Z"}]`))
		case "/api/nginx/certificates/3/download":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(bundle.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer npm.Close()

	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	connection := migrationRequest{Source: "npm", Mode: "live", URL: npm.URL, Username: "admin@example.com", Secret: "secret"}
	rec := migrationPost(t, srv, token, csrf, connection)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d: %s", rec.Code, rec.Body.String())
	}
	var p migrationPreview
	decodeJSON(t, rec, &p)
	if len(p.Certificates) != 1 || !p.Certificates[0].Importable {
		t.Fatalf("certificates = %+v", p.Certificates)
	}
	if p.Hosts[0].CertRef != "npm:3" || p.Hosts[0].CertName != "live cert" {
		t.Fatalf("host certificate = %+v", p.Hosts[0])
	}

	body, _ := json.Marshal(migrationApply{
		Source: p.Source, Hosts: p.Hosts, Redirects: p.Redirects, AccessLists: p.AccessLists,
		Connection: connection,
	})
	rec = postJSON(t, srv, token, csrf, "/api/migrate/apply", string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("apply = %d: %s", rec.Code, rec.Body.String())
	}
	var result migrationResult
	decodeJSON(t, rec, &result)
	if result.Created != 1 || len(result.Problems) != 0 {
		t.Fatalf("result = %+v", result)
	}
	certs, err := st.ListCerts()
	if err != nil || len(certs) != 1 {
		t.Fatalf("certs = %+v, %v", certs, err)
	}
	host, err := st.ProxyByHost("live.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if host.CertID == nil || *host.CertID != certs[0].ID {
		t.Fatalf("proxy cert_id = %v, certs = %+v", host.CertID, certs)
	}
}
