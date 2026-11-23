package rbac

import (
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func TestAllowsWriteImpliesRead(t *testing.T) {
	perms := []string{Permission("policies", "write")}
	if !Allows(perms, Permission("policies", "read")) {
		t.Fatal("a write grant must imply read")
	}
	if Allows(perms, Permission("proxies", "read")) {
		t.Fatal("a grant in one area must not leak into another")
	}
	if !Allows([]string{Admin}, Permission("accounts", "write")) {
		t.Fatal("the wildcard must grant everything")
	}
	if Allows(nil, Permission("dashboard", "read")) {
		t.Fatal("an empty list must grant nothing")
	}
}

func TestNormalizeRejectsUnknown(t *testing.T) {
	got := Normalize([]string{"dashboard.write", "dashboard.read", "nope", " dashboard.write ", ""})
	want := []string{"dashboard.read", "dashboard.write"}
	if len(got) != len(want) {
		t.Fatalf("normalize = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("normalize = %v, want %v", got, want)
		}
	}
}

// TestHostAdminCannotManageSites pins the role the console keys its switcher
// and Sites page off: it edits its own site and never the set of sites.
func TestHostAdminCannotManageSites(t *testing.T) {
	var hostAdmin *model.Role
	for _, role := range Builtins() {
		if role.Name == HostAdmin {
			r := role
			hostAdmin = &r
		}
	}
	if hostAdmin == nil {
		t.Fatal("the host_admin role is not built in")
	}
	if Allows(hostAdmin.Permissions, Permission("sites", "read")) {
		t.Fatal("host_admin must not read the sites list")
	}
	if !Allows(hostAdmin.Permissions, Permission("proxies", "write")) || !Allows(hostAdmin.Permissions, Permission("settings", "write")) {
		t.Fatal("host_admin must still run its own site")
	}
}

func TestBuiltinsCoverEveryArea(t *testing.T) {
	roles := Builtins()
	if len(roles) != 5 {
		t.Fatalf("built-ins = %d, want 5", len(roles))
	}
	for _, role := range roles {
		if role.Name == "" || len(role.Permissions) == 0 {
			t.Fatalf("incomplete built-in role: %+v", role)
		}
		for _, p := range role.Permissions {
			if !Valid(p) {
				t.Fatalf("role %s has unknown permission %q", role.Name, p)
			}
		}
	}
	if !Allows(roles[0].Permissions, Permission("accounts", "write")) {
		t.Fatal("Administrator must manage accounts")
	}
	if Allows(roles[2].Permissions, Permission("proxies", "write")) {
		t.Fatal("Read-only must not be able to change proxies")
	}
}
