package api

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/consoleauth"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func TestConsoleAuthStoresSecretsSealedAndRedacted(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	adminRole := st.AdminRoleID()
	body := `{"enabled":true,"host":"tacacs.example.test","port":49,"secret":"shared-secret",` +
		`"timeout_seconds":8,"default_role_id":` + jsonNumber(adminRole) + `,"role_map":"15=Administrator"}`
	rec := sendJSON(t, srv, http.MethodPut, token, csrf, "/api/console-auth/tacacs", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("save status = %d: %s", rec.Code, rec.Body.String())
	}
	var saved struct {
		Secret    string `json:"secret"`
		HasSecret bool   `json:"has_secret"`
		Enabled   bool   `json:"enabled"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Secret != "" || !saved.HasSecret || !saved.Enabled {
		t.Fatalf("saved provider leaked or lost state: %+v", saved)
	}
	stored, err := st.GetConsoleAuth("tacacs")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Secret == "" || stored.Secret == "shared-secret" {
		t.Fatalf("stored secret is not sealed: %q", stored.Secret)
	}
	opened, err := srv.box.Open(stored.Secret)
	if err != nil || opened != "shared-secret" {
		t.Fatalf("opened secret = %q, %v", opened, err)
	}
	// A second PUT with a blank secret keeps the stored one.
	body = `{"enabled":true,"host":"tacacs.example.test","port":49,"timeout_seconds":8,` +
		`"default_role_id":` + jsonNumber(adminRole) + `,"role_map":"15=Administrator"}`
	if rec := sendJSON(t, srv, http.MethodPut, token, csrf, "/api/console-auth/tacacs", body); rec.Code != http.StatusOK {
		t.Fatalf("resave status = %d: %s", rec.Code, rec.Body.String())
	}
	after, _ := st.GetConsoleAuth("tacacs")
	if after.Secret != stored.Secret {
		t.Fatal("a blank secret replaced the stored one")
	}
}

func TestConsoleAuthRejectsBadRoleMapAndRadiusWithoutRole(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	rec := sendJSON(t, srv, http.MethodPut, token, csrf, "/api/console-auth/tacacs",
		`{"enabled":true,"host":"tacacs.example.test","secret":"x","default_role_id":0,"role_map":"15=NoSuchRole"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown role map status = %d: %s", rec.Code, rec.Body.String())
	}
	rec = sendJSON(t, srv, http.MethodPut, token, csrf, "/api/console-auth/radius",
		`{"enabled":true,"host":"radius.example.test","secret":"x","default_role_id":0}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("radius without role status = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRadiusLoginProvisionsTheExternalAdministrator(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	acceptAnyRADIUS(t, "radius-secret")
	adminRole := st.AdminRoleID()
	body := `{"enabled":true,"host":"127.0.0.1","port":` + jsonInt(radiusPort) + `,"secret":"radius-secret",` +
		`"timeout_seconds":3,"default_role_id":` + jsonNumber(adminRole) + `}`
	if rec := sendJSON(t, srv, http.MethodPut, token, csrf, "/api/console-auth/radius", body); rec.Code != http.StatusOK {
		t.Fatalf("save radius = %d: %s", rec.Code, rec.Body.String())
	}

	login := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"bob","password":"hunter2"}`))
	login.Host = "gui.local"
	login.RemoteAddr = "10.0.0.10:5000"
	login.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, login)
	if rec.Code != http.StatusOK {
		t.Fatalf("external login = %d: %s", rec.Code, rec.Body.String())
	}
	user, err := st.UserByUsername("bob")
	if err != nil {
		t.Fatal(err)
	}
	if user.AuthSource != "radius" || user.RoleID != adminRole {
		t.Fatalf("provisioned user = %+v", user)
	}
	if user.PasswordHash != "" {
		t.Fatal("an external account was given a local password")
	}
}

func TestRoleForExternalMapsTACACSAndLDAPAttributes(t *testing.T) {
	srv, st, _, _ := newObservabilityServer(t)
	roles, err := st.ListRoles()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]int64{}
	for _, r := range roles {
		byName[r.Name] = r.ID
	}
	operator := byName["Operator"]
	admin := byName["Administrator"]
	if operator == 0 || admin == 0 {
		t.Fatalf("built-in roles missing: %+v", byName)
	}
	p := &model.ConsoleAuth{Kind: "tacacs", DefaultRoleID: admin, RoleMap: "15=Operator"}
	if id, name, _ := srv.roleForExternal(p, consoleauth.Result{RoleHint: "15"}); id != operator || name != "Operator" {
		t.Fatalf("priv-lvl map = %d %q, want Operator", id, name)
	}
	p = &model.ConsoleAuth{Kind: "ldap", DefaultRoleID: operator, RoleMap: "WAF-Operators=Operator\nWAF-Admins=Administrator"}
	if id, name, _ := srv.roleForExternal(p, consoleauth.Result{Groups: []string{"CN=WAF-Admins,OU=Groups,DC=test", "WAF-Admins"}}); id != admin || name != "Administrator" {
		t.Fatalf("group map = %d %q, want Administrator", id, name)
	}
	if id, _, _ := srv.roleForExternal(p, consoleauth.Result{}); id != operator {
		t.Fatalf("default role = %d, want %d", id, operator)
	}
}

func TestLocalAccountIsNotShadowedByRadius(t *testing.T) {
	srv, st, _, _ := newObservabilityServer(t)
	acceptAnyRADIUS(t, "radius-secret")
	adminRole := st.AdminRoleID()
	// The saved provider accepts any credentials.
	if err := st.SaveConsoleAuth(&model.ConsoleAuth{Kind: "radius", Enabled: true, Host: "127.0.0.1",
		Port: radiusPort, Secret: "radius-secret", TimeoutSeconds: 3, DefaultRoleID: adminRole}); err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"wrong"}`))
	login.Host = "gui.local"
	login.RemoteAddr = "10.0.0.10:5000"
	login.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, login)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("local login with a directory-approved password = %d: %s", rec.Code, rec.Body.String())
	}
	user, _ := st.UserByUsername("admin")
	if user.AuthSource != "local" {
		t.Fatalf("the local account was changed to %q", user.AuthSource)
	}
}

var radiusPort int

func acceptAnyRADIUS(t *testing.T, secret string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	radiusPort = pc.LocalAddr().(*net.UDPAddr).Port
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := append([]byte(nil), buf[:n]...)
			if len(req) < 20 {
				continue
			}
			reply := make([]byte, 20)
			reply[0] = 2 // Access-Accept
			reply[1] = req[1]
			binary.BigEndian.PutUint16(reply[2:4], 20)
			copy(reply[4:20], req[4:20])
			sum := md5.New()
			sum.Write(reply[:4])
			sum.Write(req[4:20])
			sum.Write([]byte(secret))
			copy(reply[4:20], sum.Sum(nil))
			_, _ = pc.WriteTo(reply, addr)
		}
	}()
}

func jsonNumber(n int64) string { return strconv.FormatInt(n, 10) }

func jsonInt(n int) string { return strconv.Itoa(n) }
