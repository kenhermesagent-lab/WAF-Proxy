package api

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func migrationPost(t *testing.T, srv *Server, token, csrf string, in any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	return postJSON(t, srv, token, csrf, "/api/migrate/preview", string(body))
}

func postMigrationApply(t *testing.T, srv *Server, token, csrf string, p *migrationPreview) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(migrationApply{
		Source: p.Source, Hosts: p.Hosts, Redirects: p.Redirects, AccessLists: p.AccessLists,
	})
	if err != nil {
		t.Fatal(err)
	}
	return postJSON(t, srv, token, csrf, "/api/migrate/apply", string(body))
}

func npmEnvelope(t *testing.T) string {
	t.Helper()
	doc := `{
	  "proxy_hosts": [
	    {"domain_names":["app.example.com"],"forward_scheme":"http","forward_host":"10.0.0.5","forward_port":8080,
	     "access_list_id":1,"certificate_id":7,"ssl_forced":true,"enabled":true},
	    {"domain_names":["api.example.com"],"forward_scheme":"https","forward_host":"10.0.0.6","forward_port":8443}
	  ],
	  "access_lists": [
	    {"id":1,"name":"office","clients":[
	      {"address":"10.0.0.0/8","directive":"allow"},
	      {"address":"10.9.9.9","directive":"deny"}
	    ],"items":[{"username":"guest"}]}
	  ],
	  "redirection_hosts": [
	    {"domain_names":["go.example.com"],"forward_scheme":"https","forward_domain_name":"new.example.com",
	     "forward_http_code":301,"preserve_path":true},
	    {"domain_names":["temp.example.com"],"forward_scheme":"https","forward_domain_name":"new.example.com",
	     "forward_http_code":302,"preserve_path":false}
	  ]
	}`
	return base64.StdEncoding.EncodeToString([]byte(doc))
}

func TestMigrationNPMUploadPreviewsAndApplies(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}

	rec := migrationPost(t, srv, token, csrf, migrationRequest{
		Source: "npm", Mode: "upload", Content: npmEnvelope(t),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d: %s", rec.Code, rec.Body.String())
	}
	var p migrationPreview
	decodeJSON(t, rec, &p)
	if len(p.Hosts) != 2 || len(p.Redirects) != 2 || len(p.AccessLists) != 1 {
		t.Fatalf("preview = %+v", p)
	}
	if p.Redirects[1].Status != 302 {
		t.Fatalf("302 redirect became %d", p.Redirects[1].Status)
	}
	if p.Hosts[0].Problem != "" || p.Hosts[0].AccessList != "office" || !p.Hosts[0].TLS {
		t.Fatalf("first host = %+v", p.Hosts[0])
	}
	if p.AccessLists[0].AuthUsers != 1 || len(p.AccessLists[0].Allow) != 1 || len(p.AccessLists[0].Deny) != 1 {
		t.Fatalf("access list = %+v", p.AccessLists[0])
	}

	rec = postMigrationApply(t, srv, token, csrf, &p)
	if rec.Code != http.StatusOK {
		t.Fatalf("apply = %d: %s", rec.Code, rec.Body.String())
	}
	var result migrationResult
	decodeJSON(t, rec, &result)
	if result.Created != 2 || result.Redirects != 2 || result.AccessLists != 1 || result.Skipped != 0 {
		t.Fatalf("result = %+v", result)
	}

	app, err := st.ProxyByHost("app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if app.AccessProfileID == nil {
		t.Fatal("the NPM access list was not attached")
	}
	ups, err := st.ListUpstreams(app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 1 || ups[0].URL != "http://10.0.0.5:8080" {
		t.Fatalf("upstreams = %+v", ups)
	}

	goHost, err := st.ProxyByHost("go.example.com")
	if err != nil {
		t.Fatal(err)
	}
	routes, err := st.ListRoutes(goHost.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].Target != "https://new.example.com$path" || routes[0].Status != 301 {
		t.Fatalf("routes = %+v", routes)
	}
	temp, err := st.ProxyByHost("temp.example.com")
	if err != nil {
		t.Fatal(err)
	}
	tempRoutes, err := st.ListRoutes(temp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(tempRoutes) != 1 || tempRoutes[0].Status != 302 {
		t.Fatalf("302 route = %+v", tempRoutes)
	}

	profiles, err := st.ListAccessProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || len(profiles[0].ListIDs) != 2 {
		t.Fatalf("profiles = %+v", profiles)
	}
}

func TestMigrationZoraxyZIPReadsProxyRules(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("conf/proxy/app.config")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte(`{
	  "ProxyType": 1,
	  "RootOrMatchingDomain": "app.example.com",
	  "MatchingDomainAlias": ["alias.example.com"],
	  "ActiveOrigins": [{"OriginIpOrDomain":"10.0.0.7:9000","RequireTLS":false}],
	  "VirtualDirectories": [],
	  "Disabled": false
	}`))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	rec := migrationPost(t, srv, token, csrf, migrationRequest{
		Source: "zoraxy", Mode: "upload",
		Content: base64.StdEncoding.EncodeToString(buf.Bytes()),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d: %s", rec.Code, rec.Body.String())
	}
	var p migrationPreview
	decodeJSON(t, rec, &p)
	if len(p.Hosts) != 2 {
		t.Fatalf("hosts = %+v", p.Hosts)
	}
	if p.Hosts[0].Upstreams[0] != "http://10.0.0.7:9000" {
		t.Fatalf("upstream = %q", p.Hosts[0].Upstreams[0])
	}
}

func TestMigrationLiveNPMIsReadOnlyAndScoped(t *testing.T) {
	var tokenSeen string
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tokens":
			if r.Method != http.MethodPost {
				t.Errorf("token method = %s", r.Method)
			}
			var login map[string]string
			if err := json.NewDecoder(r.Body).Decode(&login); err != nil {
				t.Errorf("login body: %v", err)
			}
			if login["identity"] != "admin@example.com" || login["secret"] != "secret" {
				t.Errorf("login fields = %+v", login)
			}
			_, _ = w.Write([]byte(`{"token":"npm-token"}`))
		case "/api/nginx/proxy-hosts":
			tokenSeen = r.Header.Get("Authorization")
			_, _ = w.Write([]byte(`[{"domain_names":["live.example.com"],"forward_scheme":"http","forward_host":"10.1.1.5","forward_port":8081}]`))
		case "/api/nginx/access-lists":
			_, _ = w.Write([]byte(`[]`))
		case "/api/nginx/redirection-hosts":
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer npm.Close()

	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	rec := migrationPost(t, srv, token, csrf, migrationRequest{
		Source: "npm", Mode: "live", URL: npm.URL, Username: "admin@example.com", Secret: "secret",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d: %s", rec.Code, rec.Body.String())
	}
	var p migrationPreview
	decodeJSON(t, rec, &p)
	if len(p.Hosts) != 1 || p.Hosts[0].Hostname != "live.example.com" {
		t.Fatalf("hosts = %+v", p.Hosts)
	}
	if tokenSeen != "Bearer npm-token" {
		t.Fatalf("authorization = %q", tokenSeen)
	}
	if _, err := st.ProxyByHost("live.example.com"); err == nil {
		t.Fatal("preview must not create a proxy")
	}
}

func TestMigrationMarksHostnamesOutsideBaseDomain(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	doc := base64.StdEncoding.EncodeToString([]byte(`{"proxy_hosts":[{"domain_names":["app.other.net"],"forward_scheme":"http","forward_host":"10.0.0.5","forward_port":80}]}`))
	rec := migrationPost(t, srv, token, csrf, migrationRequest{Source: "npm", Mode: "upload", Content: doc})
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d: %s", rec.Code, rec.Body.String())
	}
	var p migrationPreview
	decodeJSON(t, rec, &p)
	if len(p.Hosts) != 1 || p.Hosts[0].Problem == "" {
		t.Fatalf("host = %+v", p.Hosts)
	}
	rec = postMigrationApply(t, srv, token, csrf, &p)
	var result migrationResult
	decodeJSON(t, rec, &result)
	if result.Created != 0 || result.Skipped != 1 {
		t.Fatalf("result = %+v", result)
	}
}
