package api

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
)

func TestMigrationHAProxyZIPImportsPEMBundle(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t, []string{"hap.example.com"})
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := map[string]string{
		"haproxy.cfg": `frontend web
  bind *:443 ssl crt /etc/haproxy/hap.pem
  acl host_hap hdr(host) -i hap.example.com
  use_backend hap if host_hap
backend hap
  server hap1 10.0.0.8:8080
`,
		"etc/haproxy/hap.pem": certPEM + keyPEM,
	}
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	content := base64.StdEncoding.EncodeToString(buf.Bytes())

	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	rec := migrationPost(t, srv, token, csrf, migrationRequest{Source: "haproxy", Mode: "upload", Content: content})
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d: %s", rec.Code, rec.Body.String())
	}
	var p migrationPreview
	decodeJSON(t, rec, &p)
	if len(p.Certificates) != 1 || !p.Certificates[0].Importable {
		t.Fatalf("certificates = %+v", p.Certificates)
	}
	body, _ := json.Marshal(migrationApply{
		Source: p.Source, Hosts: p.Hosts, Redirects: p.Redirects, AccessLists: p.AccessLists,
		Connection: migrationRequest{Source: "haproxy", Mode: "upload", Content: content},
	})
	rec = postJSON(t, srv, token, csrf, "/api/migrate/apply", string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("apply = %d: %s", rec.Code, rec.Body.String())
	}
	if certs, err := st.ListCerts(); err != nil || len(certs) != 1 {
		t.Fatalf("certs = %+v, %v", certs, err)
	}
	if host, err := st.ProxyByHost("hap.example.com"); err != nil || host.CertID == nil {
		t.Fatalf("host = %+v, %v", host, err)
	}
}

func TestMigrationTraefikAndCaddyZIPImportCertificates(t *testing.T) {
	cases := []struct {
		name, source, configName, config string
	}{
		{
			name: "traefik", source: "traefik", configName: "traefik.yml",
			config: `tls:
  certificates:
    - certFile: /etc/traefik/certs/app.pem
      keyFile: /etc/traefik/certs/app.key
http:
  routers:
    app:
      rule: Host(` + "`app.example.com`" + `)
      service: app
      tls: {}
  services:
    app:
      loadBalancer:
        servers:
          - url: http://10.0.0.5:8080
`,
		},
		{
			name: "caddy", source: "caddy", configName: "Caddyfile",
			config: `app.example.com {
  reverse_proxy 10.0.0.5:8080
  tls /etc/caddy/certs/app.pem /etc/caddy/certs/app.key
}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			certPEM, keyPEM := selfSignedPEM(t, []string{"app.example.com"})
			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			files := map[string]string{
				tc.configName:                            tc.config,
				"etc" + "/" + tc.name + "/certs/app.pem": certPEM,
				"etc" + "/" + tc.name + "/certs/app.key": keyPEM,
			}
			for name, body := range files {
				w, err := zw.Create(name)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = w.Write([]byte(body))
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			content := base64.StdEncoding.EncodeToString(buf.Bytes())

			srv, st, token, csrf := newObservabilityServer(t)
			if err := st.SetSetting("base_domain", "example.com"); err != nil {
				t.Fatal(err)
			}
			rec := migrationPost(t, srv, token, csrf, migrationRequest{Source: tc.source, Mode: "upload", Content: content})
			if rec.Code != http.StatusOK {
				t.Fatalf("preview = %d: %s", rec.Code, rec.Body.String())
			}
			var p migrationPreview
			decodeJSON(t, rec, &p)
			if len(p.Certificates) != 1 || !p.Certificates[0].Importable {
				t.Fatalf("certificates = %+v", p.Certificates)
			}
			app := hostByHostname(t, p, "app.example.com")
			if app.CertRef == "" || app.CertKeyRef == "" {
				t.Fatalf("host certificate not attached: %+v", app)
			}
			body, _ := json.Marshal(migrationApply{
				Source: p.Source, Hosts: p.Hosts, Redirects: p.Redirects, AccessLists: p.AccessLists,
				Connection: migrationRequest{Source: tc.source, Mode: "upload", Content: content},
			})
			rec = postJSON(t, srv, token, csrf, "/api/migrate/apply", string(body))
			if rec.Code != http.StatusOK {
				t.Fatalf("apply = %d: %s", rec.Code, rec.Body.String())
			}
			certs, err := st.ListCerts()
			if err != nil || len(certs) != 1 {
				t.Fatalf("certs = %+v, %v", certs, err)
			}
			host, err := st.ProxyByHost("app.example.com")
			if err != nil || host.CertID == nil {
				t.Fatalf("host = %+v, %v", host, err)
			}
		})
	}
}

func TestMigrationApacheZIPImportsCertificate(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t, []string{"apache.example.com"})
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := map[string]string{
		"site.conf": `<VirtualHost *:443>
  ServerName apache.example.com
  SSLEngine on
  SSLCertificateFile /etc/ssl/apache/fullchain.pem
  SSLCertificateKeyFile /etc/ssl/apache/privkey.pem
  ProxyPass / http://10.0.0.9:8080/
</VirtualHost>`,
		"etc/ssl/apache/fullchain.pem": certPEM,
		"etc/ssl/apache/privkey.pem":   keyPEM,
	}
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	content := base64.StdEncoding.EncodeToString(buf.Bytes())

	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	rec := migrationPost(t, srv, token, csrf, migrationRequest{Source: "apache", Mode: "upload", Content: content})
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d: %s", rec.Code, rec.Body.String())
	}
	var p migrationPreview
	decodeJSON(t, rec, &p)
	if len(p.Certificates) != 1 || !p.Certificates[0].Importable {
		t.Fatalf("certificates = %+v", p.Certificates)
	}
	app := hostByHostname(t, p, "apache.example.com")
	if app.CertRef == "" || app.CertKeyRef == "" {
		t.Fatalf("host certificate not attached: %+v", app)
	}
	body, _ := json.Marshal(migrationApply{
		Source: p.Source, Hosts: p.Hosts, Redirects: p.Redirects, AccessLists: p.AccessLists,
		Connection: migrationRequest{Source: "apache", Mode: "upload", Content: content},
	})
	rec = postJSON(t, srv, token, csrf, "/api/migrate/apply", string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("apply = %d: %s", rec.Code, rec.Body.String())
	}
	certs, err := st.ListCerts()
	if err != nil || len(certs) != 1 {
		t.Fatalf("certs = %+v, %v", certs, err)
	}
	host, err := st.ProxyByHost("apache.example.com")
	if err != nil || host.CertID == nil {
		t.Fatalf("host = %+v, %v", host, err)
	}
}

func TestMigrationNginxZIPImportsCertificate(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t, []string{"zip.example.com"})
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := map[string]string{
		"proxy-confs/zip.conf": `server {
  listen 443 ssl;
  server_name zip.example.com;
  ssl_certificate /config/etc/letsencrypt/live/zip/fullchain.pem;
  ssl_certificate_key /config/etc/letsencrypt/live/zip/privkey.pem;
  location / { proxy_pass http://10.0.0.9:8080; }
}`,
		"etc/letsencrypt/live/zip/fullchain.pem": certPEM,
		"etc/letsencrypt/live/zip/privkey.pem":   keyPEM,
	}
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	content := base64.StdEncoding.EncodeToString(buf.Bytes())

	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	rec := migrationPost(t, srv, token, csrf, migrationRequest{Source: "nginx", Mode: "upload", Content: content})
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d: %s", rec.Code, rec.Body.String())
	}
	var p migrationPreview
	decodeJSON(t, rec, &p)
	if len(p.Certificates) != 1 || !p.Certificates[0].Importable {
		t.Fatalf("certificates = %+v", p.Certificates)
	}
	body, _ := json.Marshal(migrationApply{
		Source: p.Source, Hosts: p.Hosts, Redirects: p.Redirects, AccessLists: p.AccessLists,
		Connection: migrationRequest{Source: "nginx", Mode: "upload", Content: content},
	})
	rec = postJSON(t, srv, token, csrf, "/api/migrate/apply", string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("apply = %d: %s", rec.Code, rec.Body.String())
	}
	certs, err := st.ListCerts()
	if err != nil || len(certs) != 1 {
		t.Fatalf("certs = %+v, %v", certs, err)
	}
	host, err := st.ProxyByHost("zip.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if host.CertID == nil {
		t.Fatal("ZIP certificate was not attached")
	}
}
