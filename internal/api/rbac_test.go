package api

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/rbac"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func TestPermissionForMapsRoutes(t *testing.T) {
	cases := []struct {
		method, path, want string
	}{
		{http.MethodGet, "/api/metrics", "dashboard.read"},
		{http.MethodGet, "/api/events", "traffic.read"},
		{http.MethodPost, "/api/proxies", "proxies.write"},
		{http.MethodGet, "/api/certs", "certificates.read"},
		{http.MethodPost, "/api/migrate/preview", "proxies.write"},
		{http.MethodPost, "/api/migrate/apply", "proxies.write"},
		{http.MethodPost, "/api/feeds", "sources.write"},
		{http.MethodGet, "/api/users", "accounts.read"},
		{http.MethodGet, "/api/sessions", "accounts.read"},
		{http.MethodGet, "/api/console-auth", "accounts.read"},
		{http.MethodPut, "/api/console-auth/tacacs", "accounts.write"},
		{http.MethodPut, "/api/settings", "settings.write"},
		{http.MethodPost, "/api/updates/apply", "system.write"},
		{http.MethodGet, "/api/protection-profiles/audit", "policies.read"},
		{http.MethodPost, "/api/simulate", "policies.read"},
		{http.MethodGet, "/api/me", ""},
		{http.MethodPost, "/api/account/password", ""},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		if got := permissionFor(r); got != tc.want {
			t.Errorf("%s %s = %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
}

func TestMigrationWritesNeedResourcePermissions(t *testing.T) {
	srv, st, _, _ := newObservabilityServer(t)
	role := &model.Role{
		Name: "Proxy operator",
		Permissions: []string{
			rbac.Permission("proxies", "write"),
			rbac.Permission("certificates", "read"),
		},
	}
	if err := st.CreateRole(role); err != nil {
		t.Fatal(err)
	}
	uid, err := st.CreateUserWithRole("proxy-only", "unused", "", "", false, role.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession("proxy-token", uid, "proxy-csrf", "10.0.0.12", "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := selfSignedPEM(t, []string{"app.example.com"})
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := map[string]string{
		"app.conf": `server {
  listen 443 ssl;
  server_name app.example.com;
  ssl_certificate /etc/ssl/app/fullchain.pem;
  ssl_certificate_key /etc/ssl/app/privkey.pem;
  location / { proxy_pass http://10.0.0.5:8080; }
}`,
		"etc/ssl/app/fullchain.pem": certPEM,
		"etc/ssl/app/privkey.pem":   keyPEM,
	}
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(content))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	content := base64.StdEncoding.EncodeToString(buf.Bytes())

	body, _ := json.Marshal(migrationApply{
		Source: "nginx",
		Hosts: []migrationHost{{
			Hostname: "app.example.com", Upstreams: []string{"http://10.0.0.5:8080"},
			Enabled: true, CertRef: "/etc/ssl/app/fullchain.pem", CertKeyRef: "/etc/ssl/app/privkey.pem",
			AccessList: "office",
		}},
		AccessLists: []migrationAccessList{{Name: "office", Allow: []string{"203.0.113.10"}}},
		Connection:  migrationRequest{Source: "nginx", Mode: "upload", Content: content},
	})
	rec := postJSON(t, srv, "proxy-token", "proxy-csrf", "/api/migrate/apply", string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("apply with certificate = %d: %s", rec.Code, rec.Body.String())
	}
	var result migrationResult
	decodeJSON(t, rec, &result)
	problems := strings.Join(result.Problems, " ")
	if result.Certificates != 0 || !strings.Contains(problems, "certificates.write") {
		t.Fatalf("certificate was imported without permission: %+v", result)
	}
	if result.AccessLists != 0 || !strings.Contains(problems, "policies.write") {
		t.Fatalf("access list was imported without permission: %+v", result)
	}
	if certs, err := st.ListCerts(); err != nil || len(certs) != 0 {
		t.Fatalf("certificates created without permission: %+v, %v", certs, err)
	}
	if lists, err := st.ListAccessLists(); err != nil || len(lists) != 0 {
		t.Fatalf("access lists created without permission: %+v, %v", lists, err)
	}
	if host, err := st.ProxyByHost("app.example.com"); err != nil || host.CertID != nil || host.AccessProfileID != nil {
		t.Fatalf("host should import without a certificate or access list: %+v, %v", host, err)
	}
}

func TestViewerIsRefusedOutsideItsPages(t *testing.T) {
	srv, st, _, _ := newObservabilityServer(t)
	roles, err := st.ListRoles()
	if err != nil {
		t.Fatal(err)
	}
	var viewer int64
	for _, r := range roles {
		if r.Name == "Viewer" {
			viewer = r.ID
		}
	}
	if viewer == 0 {
		t.Fatal("Viewer role missing")
	}
	uid, err := st.CreateUserWithRole("watcher", "hash", "", "", false, viewer)
	if err != nil {
		t.Fatal(err)
	}
	token := "viewer-token"
	if err := st.CreateSession(token, uid, "csrf", "10.0.0.10", "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	get := func(path string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "gui.local"
		req.RemoteAddr = "10.0.0.10:5000"
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	if code := get("/api/metrics"); code != http.StatusOK {
		t.Fatalf("viewer GET /api/metrics = %d, want 200", code)
	}
	if code := get("/api/proxies"); code != http.StatusForbidden {
		t.Fatalf("viewer GET /api/proxies = %d, want 403", code)
	}
	if code := get("/api/users"); code != http.StatusForbidden {
		t.Fatalf("viewer GET /api/users = %d, want 403", code)
	}
}

func TestAdministratorManagesAccounts(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)

	rec := authed(t, srv, token, csrf, http.MethodGet, "/api/users", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/users = %d: %s", rec.Code, rec.Body.String())
	}
	var listing struct {
		Users []store.UserSummary `json:"users"`
		Roles []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"roles"`
		Areas []rbac.Area `json:"areas"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listing); err != nil {
		t.Fatal(err)
	}
	if len(listing.Users) != 1 || len(listing.Roles) != 5 || len(listing.Areas) == 0 {
		t.Fatalf("unexpected listing: %+v", listing)
	}

	body := `{"username":"operator","password":"a sufficiently long password","role_id":` + strconv.FormatInt(listing.Roles[1].ID, 10) + `}`
	created := authed(t, srv, token, csrf, http.MethodPost, "/api/users", body)
	if created.Code != http.StatusCreated {
		t.Fatalf("POST /api/users = %d: %s", created.Code, created.Body.String())
	}
	var out struct {
		TotpSecret string `json:"totp_secret"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &out); err != nil || out.TotpSecret == "" {
		t.Fatalf("new account must return an authenticator secret: %s", created.Body.String())
	}
	dup := authed(t, srv, token, csrf, http.MethodPost, "/api/users", body)
	if dup.Code != http.StatusConflict {
		t.Fatalf("duplicate account = %d, want 409", dup.Code)
	}
}

func TestAdminAllowlistValidation(t *testing.T) {
	clean, msg := validateAdminAllowlist(" 192.168.0.0/16 , 203.0.113.9 ", "192.168.1.20")
	if msg != "" {
		t.Fatalf("valid list rejected: %s", msg)
	}
	if !strings.Contains(clean, "203.0.113.9/32") {
		t.Fatalf("bare address not canonicalised: %q", clean)
	}
	if _, msg := validateAdminAllowlist("203.0.113.0/24", "192.168.1.20"); !strings.Contains(msg, "lock you out") {
		t.Fatalf("lockout list accepted: %q", msg)
	}
	if _, msg := validateAdminAllowlist("not-a-cidr", "192.168.1.20"); msg == "" {
		t.Fatal("invalid CIDR accepted")
	}
	if clean, msg := validateAdminAllowlist("", "192.168.1.20"); msg != "" || clean != "" {
		t.Fatalf("empty list should disable the rule: %q %q", clean, msg)
	}
}

func TestHostAllowlistIsEnforced(t *testing.T) {
	srv, st, token, _ := newObservabilityServer(t)
	if err := st.SetSetting("admin_allow_cidrs", "192.168.0.0/16"); err != nil {
		t.Fatal(err)
	}
	if err := srv.loadAdminAllowlist(); err != nil {
		t.Fatal(err)
	}
	get := func(remote string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
		req.Host = "gui.local"
		req.RemoteAddr = remote
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	if code := get("192.168.1.20:5000"); code != http.StatusOK {
		t.Fatalf("allowed address = %d, want 200", code)
	}
	if code := get("203.0.113.7:5000"); code != http.StatusForbidden {
		t.Fatalf("disallowed address = %d, want 403", code)
	}
	if err := st.SetSetting("admin_allow_cidrs", ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.loadAdminAllowlist(); err != nil {
		t.Fatal(err)
	}
	if code := get("203.0.113.7:5000"); code != http.StatusOK {
		t.Fatalf("cleared allowlist = %d, want 200", code)
	}
}
