package api

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func uploadPreview(t *testing.T, srv *Server, token, csrf, source string, data []byte) migrationPreview {
	t.Helper()
	rec := migrationPost(t, srv, token, csrf, migrationRequest{
		Source: source, Mode: "upload",
		Content: base64.StdEncoding.EncodeToString(data),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("%s preview = %d: %s", source, rec.Code, rec.Body.String())
	}
	var p migrationPreview
	decodeJSON(t, rec, &p)
	return p
}

func hostByHostname(t *testing.T, p migrationPreview, hostname string) migrationHost {
	t.Helper()
	for _, h := range p.Hosts {
		if h.Hostname == hostname {
			return h
		}
	}
	t.Fatalf("%s not in %+v", hostname, p.Hosts)
	return migrationHost{}
}

func TestAddHostReplacesAnEarlierRedirect(t *testing.T) {
	p := &migrationPreview{}
	p.addRedirect(migrationRedirect{Hostname: "app.example.com", Target: "https://new.example.com", Status: 301})
	p.addHost(migrationHost{Hostname: "app.example.com", Upstreams: []string{"http://10.0.0.5:8080"}, Enabled: true})
	if len(p.Redirects) != 0 {
		t.Fatalf("redirect survived a proxy for the same host: %+v", p.Redirects)
	}
}

func TestAddHostKeepsCertificateKeyWhenMerging(t *testing.T) {
	p := &migrationPreview{}
	p.addHost(migrationHost{Hostname: "app.example.com", Upstreams: []string{"http://10.0.0.5:8080"}, Enabled: true, CertRef: "cert.pem", CertKeyRef: "key.pem", CertName: "cert.pem"})
	p.addHost(migrationHost{Hostname: "app.example.com", Upstreams: []string{"http://10.0.0.6:8080"}, Enabled: true})
	if p.Hosts[0].CertRef != "cert.pem" || p.Hosts[0].CertKeyRef != "key.pem" {
		t.Fatalf("certificate pair lost while merging: %+v", p.Hosts[0])
	}
}

func TestMigrationTraefikUpload(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	p := uploadPreview(t, srv, token, csrf, "traefik", []byte(`
http:
  routers:
    app:
      rule: Host(`+"`app.example.com`"+`)
      service: app
      tls: {}
    api:
      rule: Host(`+"`api.example.com`, `www.example.com`"+`)
      service: api
  services:
    app:
      loadBalancer:
        servers:
          - url: http://10.0.0.5:8080
    api:
      loadBalancer:
        servers:
          - url: https://10.0.0.6:8443
`))
	if len(p.Hosts) != 3 {
		t.Fatalf("hosts = %+v", p.Hosts)
	}
	app := hostByHostname(t, p, "app.example.com")
	if !app.TLS || len(app.Upstreams) != 1 || app.Upstreams[0] != "http://10.0.0.5:8080" {
		t.Fatalf("app = %+v", app)
	}
	if got := hostByHostname(t, p, "api.example.com").Upstreams[0]; got != "https://10.0.0.6:8443" {
		t.Fatalf("api upstream = %q", got)
	}
}

func TestMigrationCaddyfileUpload(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	p := uploadPreview(t, srv, token, csrf, "caddy", []byte(`
{
  email admin@example.com
}

app.example.com, www.example.com {
  reverse_proxy 10.0.0.5:8080
  tls internal
}

go.example.com {
  redir https://new.example.com{uri} permanent
}
`))
	app := hostByHostname(t, p, "app.example.com")
	if !app.TLS || len(app.Upstreams) != 1 || app.Upstreams[0] != "http://10.0.0.5:8080" {
		t.Fatalf("app = %+v", app)
	}
	if len(p.Redirects) != 1 || p.Redirects[0].Target != "https://new.example.com$path" || p.Redirects[0].Status != 301 {
		t.Fatalf("redirects = %+v", p.Redirects)
	}
}

func TestMigrationNginxUpload(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	p := uploadPreview(t, srv, token, csrf, "nginx", []byte(`
upstream api {
  server 10.0.0.6:9000;
}

server {
  listen 443 ssl http2;
  server_name app.example.com www.example.com;
  ssl_certificate /etc/ssl/app/fullchain.pem;
  ssl_certificate_key /etc/ssl/app/privkey.pem;
  location / {
    proxy_pass http://10.0.0.5:8080;
  }
}

server {
  listen 80;
  server_name go.example.com;
  return 301 https://new.example.com$request_uri;
}

server {
  listen 443 ssl;
  server_name api.example.com;
  location / {
    proxy_pass http://api;
  }
}
`))
	app := hostByHostname(t, p, "app.example.com")
	if !app.TLS || app.Upstreams[0] != "http://10.0.0.5:8080" {
		t.Fatalf("app = %+v", app)
	}
	if got := hostByHostname(t, p, "api.example.com").Upstreams[0]; got != "http://10.0.0.6:9000" {
		t.Fatalf("upstream resolution = %q", got)
	}
	if len(p.Redirects) != 1 || p.Redirects[0].Target != "https://new.example.com$path" || p.Redirects[0].Status != 301 {
		t.Fatalf("redirects = %+v", p.Redirects)
	}
	if len(p.Certificates) != 1 || p.Certificates[0].Importable {
		t.Fatalf("certificates = %+v", p.Certificates)
	}
}

func TestMigrationHAProxyUpload(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	p := uploadPreview(t, srv, token, csrf, "haproxy", []byte(`
frontend web
  bind *:443 ssl crt /etc/ssl/site.pem
  acl host_app hdr(host) -i app.example.com
  acl host_api hdr(host) -i api.example.com
  use_backend app if host_app
  use_backend api if host_api

backend app
  server app1 10.0.0.5:8080 check

backend api
  server api1 10.0.0.6:8443 ssl check
`))
	app := hostByHostname(t, p, "app.example.com")
	if !app.TLS || app.Upstreams[0] != "http://10.0.0.5:8080" {
		t.Fatalf("app = %+v", app)
	}
	api := hostByHostname(t, p, "api.example.com")
	if api.Upstreams[0] != "https://10.0.0.6:8443" {
		t.Fatalf("api = %+v", api)
	}
}

func TestMigrationHAProxyDefaultBackend(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	p := uploadPreview(t, srv, token, csrf, "haproxy", []byte(`
frontend web
  bind *:443 ssl crt /etc/ssl/site.pem
  acl host_app hdr(host) -i app.example.com
  default_backend app

backend app
  server app1 10.0.0.5:8080 check
`))
	app := hostByHostname(t, p, "app.example.com")
	if len(app.Upstreams) != 1 || app.Upstreams[0] != "http://10.0.0.5:8080" {
		t.Fatalf("default backend not resolved: %+v", app)
	}
}

func TestMigrationApacheUpload(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	p := uploadPreview(t, srv, token, csrf, "apache", []byte(`
<VirtualHost *:443>
  ServerName app.example.com
  ServerAlias www.example.com
  SSLEngine on
  SSLCertificateFile /etc/ssl/app/fullchain.pem
  SSLCertificateKeyFile /etc/ssl/app/privkey.pem
  ProxyPass / http://10.0.0.5:8080/
</VirtualHost>

<VirtualHost *:80>
  ServerName go.example.com
  Redirect permanent / https://new.example.com/
</VirtualHost>
`))
	app := hostByHostname(t, p, "app.example.com")
	if !app.TLS || app.Upstreams[0] != "http://10.0.0.5:8080/" {
		t.Fatalf("app = %+v", app)
	}
	if len(p.Redirects) != 1 || p.Redirects[0].Status != 301 {
		t.Fatalf("redirects = %+v", p.Redirects)
	}
}

func TestMigrationLiveTraefikAndCaddy(t *testing.T) {
	traefik := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/http/routers":
			_, _ = w.Write([]byte(`[{"name":"app","rule":"Host(` + "`live.example.com`" + `)","service":"app","tls":{}}]`))
		case "/api/http/services":
			_, _ = w.Write([]byte(`[{"name":"app","loadBalancer":{"servers":[{"url":"http://10.0.0.5:8080"}]}}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer traefik.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/config/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[{"match":[{"host":["caddy.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.7:9000"}]}]}]}}}}}`))
	}))
	defer caddy.Close()

	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	for source, url := range map[string]string{"traefik": traefik.URL, "caddy": caddy.URL} {
		rec := migrationPost(t, srv, token, csrf, migrationRequest{Source: source, Mode: "live", URL: url})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s = %d: %s", source, rec.Code, rec.Body.String())
		}
		var p migrationPreview
		decodeJSON(t, rec, &p)
		if len(p.Hosts) != 1 || p.Hosts[0].Hostname == "" || len(p.Hosts[0].Upstreams) != 1 {
			t.Fatalf("%s preview = %+v", source, p)
		}
	}
}
