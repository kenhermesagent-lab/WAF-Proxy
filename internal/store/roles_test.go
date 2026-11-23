package store

import (
	"errors"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/rbac"
)

func TestRolesSeedAndAssign(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	roles, err := st.ListRoles()
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 5 {
		t.Fatalf("seeded roles = %d, want 5", len(roles))
	}
	viewer := findRole(t, roles, "Viewer")

	id, err := st.CreateUserWithRole("viewer", "hash", "", "", false, viewer.ID)
	if err != nil {
		t.Fatal(err)
	}
	user, err := st.UserByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if user.RoleID != viewer.ID {
		t.Fatalf("role id = %d, want %d", user.RoleID, viewer.ID)
	}

	if err := st.CreateSession("token", id, "csrf", "127.0.0.1", "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	sess, err := st.LookupSession("token")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Role != "Viewer" {
		t.Fatalf("session role = %q, want Viewer", sess.Role)
	}
	if !sess.Can("dashboard.read") || sess.Can("policies.write") {
		t.Fatalf("viewer permissions = %v", sess.Permissions)
	}
}

func TestCustomRoleLifecycle(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	role := &model.Role{Name: "Auditor", Description: "traffic only",
		Permissions: []string{rbac.Permission("traffic", "read")}}
	if err := st.CreateRole(role); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateRole(&model.Role{Name: "Auditor", Permissions: []string{"dashboard.read"}}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate role error = %v, want ErrDuplicate", err)
	}

	admin := st.AdminRoleID()
	uid, err := st.CreateUserWithRole("auditor", "hash", "", "", false, role.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteRole(role.ID); err == nil {
		t.Fatal("a role still assigned to an account must not be deleted")
	}
	if err := st.UpdateUserRole(uid, admin); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteRole(role.ID); err != nil {
		t.Fatal(err)
	}

	builtin := findRole(t, mustRoles(t, st), "Administrator")
	if err := st.DeleteRole(builtin.ID); err == nil {
		t.Fatal("built-in roles must not be deleted")
	}
}

func TestLastAdministratorCount(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.CreateUser("admin", "hash", "", "", false); err != nil {
		t.Fatal(err)
	}
	if n, err := st.AdministratorCount(); err != nil || n != 1 {
		t.Fatalf("administrators = %d (%v), want 1", n, err)
	}
	if st.AdminRoleID() == 0 {
		t.Fatal("the administrator role was not seeded")
	}
}

func mustRoles(t *testing.T, st *Store) []model.Role {
	t.Helper()
	roles, err := st.ListRoles()
	if err != nil {
		t.Fatal(err)
	}
	return roles
}

func findRole(t *testing.T, roles []model.Role, name string) model.Role {
	t.Helper()
	for _, r := range roles {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("role %q not found", name)
	return model.Role{}
}

func TestCertChallengeRoundTrip(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, err := st.SaveCert(&model.Cert{Domains: "app.example.com", Provider: "http-01", Status: "pending", Challenge: model.CertChallengeHTTP})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := st.GetCert(id)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Challenge != model.CertChallengeHTTP {
		t.Fatalf("challenge = %q, want %q", cert.Challenge, model.CertChallengeHTTP)
	}
	cert.Challenge = model.CertChallengeTLSALPN
	if _, err := st.SaveCert(cert); err != nil {
		t.Fatal(err)
	}
	listed, err := st.ListCerts()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Challenge != model.CertChallengeTLSALPN {
		t.Fatalf("listed certs = %+v", listed)
	}
}
