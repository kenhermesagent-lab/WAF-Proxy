package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/netmatch"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/rbac"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// permissionFor maps an API path to the permission it needs. Self-service
// account routes return "" because every signed-in user may manage their own
// password and authenticator.
func permissionFor(r *http.Request) string {
	path := r.URL.Path
	if path == "/api/me" || path == "/api/logout" || path == "/api/search" || strings.HasPrefix(path, "/api/account/") {
		return ""
	}
	// A simulation is read-only despite being a POST.
	if path == "/api/simulate" {
		return rbac.Permission("policies", "read")
	}
	// A rollback checks the owning entity's write permission itself, because
	// the area depends on the audited entity rather than the route.
	if path != "/api/audit" && strings.HasPrefix(path, "/api/audit") && r.Method == http.MethodPost {
		return ""
	}
	area := "settings"
	switch {
	case strings.HasPrefix(path, "/api/users"), strings.HasPrefix(path, "/api/roles"):
		area = "accounts"
	case strings.HasPrefix(path, "/api/metrics"), strings.HasPrefix(path, "/api/globe"),
		strings.HasPrefix(path, "/api/uptime"), path == "/api/stream":
		area = "dashboard"
	case strings.HasPrefix(path, "/api/events"), strings.HasPrefix(path, "/api/log-views"),
		strings.HasPrefix(path, "/api/analytics"),
		strings.HasPrefix(path, "/api/ips"), strings.HasPrefix(path, "/api/audit"),
		strings.HasPrefix(path, "/api/gate-failures"), strings.HasPrefix(path, "/api/anomaly"):
		area = "traffic"
	case strings.HasPrefix(path, "/api/proxies"), strings.HasPrefix(path, "/api/presets"):
		area = "proxies"
	case strings.HasPrefix(path, "/api/streaming"):
		area = "streaming"
	case strings.HasPrefix(path, "/api/certs"):
		area = "certificates"
	case strings.HasPrefix(path, "/api/feeds"), strings.HasPrefix(path, "/api/agents"),
		strings.HasPrefix(path, "/api/intel"), strings.HasPrefix(path, "/api/crowdsec"),
		strings.HasPrefix(path, "/api/bundles"):
		area = "sources"
	case strings.HasPrefix(path, "/api/policies"), strings.HasPrefix(path, "/api/bans"),
		strings.HasPrefix(path, "/api/lists"), strings.HasPrefix(path, "/api/access-profiles"),
		strings.HasPrefix(path, "/api/protection-profiles"), strings.HasPrefix(path, "/api/profiles"),
		strings.HasPrefix(path, "/api/auth-providers"), strings.HasPrefix(path, "/api/gate-users"):
		area = "policies"
	case strings.HasPrefix(path, "/api/sites"):
		area = "sites"
	case strings.HasPrefix(path, "/api/updates"):
		area = "system"
	}
	action := "write"
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		action = "read"
	}
	return rbac.Permission(area, action)
}

// authorize refuses a request whose session lacks the route's permission.
func (s *Server) authorize(sess *store.Session, r *http.Request) bool {
	// Without a role (a database from before RBAC that has not been migrated),
	// fall back to full access rather than locking the operator out.
	if sess.Role == "" && len(sess.Permissions) == 0 {
		return true
	}
	want := permissionFor(r)
	return want == "" || sess.Can(want)
}

// loadAdminAllowlist installs the source allowlist for the console. An empty
// list means every address may sign in; otherwise only the listed prefixes can
// reach the login form or the authenticated API.
func (s *Server) loadAdminAllowlist() error {
	raw, err := s.st.GetSetting("admin_allow_cidrs")
	if err != nil {
		return err
	}
	set := netmatch.New[bool]()
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netmatch.ParsePrefix(part)
		if err != nil {
			return fmt.Errorf("invalid admin allowlist entry %q", part)
		}
		set.AddPrefix(p, true)
	}
	if set.Len() == 0 {
		s.adminNets.Store(nil)
		return nil
	}
	s.adminNets.Store(set)
	return nil
}

// adminAddressAllowed reports whether ip may use the admin console.
func (s *Server) adminAddressAllowed(ip string) bool {
	set := s.adminNets.Load()
	if set == nil {
		return true
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	_, ok := set.Match(addr)
	return ok
}

// validateAdminAllowlist parses the list and refuses a change that would lock
// the caller out of the console they are saving from.
func validateAdminAllowlist(raw, callerIP string) (string, string) {
	set := netmatch.New[bool]()
	cleaned := []string{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netmatch.ParsePrefix(part)
		if err != nil {
			return "", "invalid admin allowlist entry: " + part
		}
		set.AddPrefix(p, true)
		cleaned = append(cleaned, p.String())
	}
	sort.Strings(cleaned)
	if set.Len() > 0 {
		addr, err := netip.ParseAddr(strings.TrimSpace(callerIP))
		if err != nil {
			return "", "the admin allowlist needs a concrete caller address; refusing to save it"
		}
		if _, ok := set.Match(addr); !ok {
			return "", "this allowlist would lock you out: your current address " + callerIP + " is not included"
		}
	}
	return strings.Join(cleaned, ","), ""
}

// ---------- users and roles ----------

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.db(r).ListUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	roles, err := s.db(r).ListRoles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users, "roles": roles, "areas": rbac.Areas})
}

type userBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
	RoleID   int64  `json:"role_id"`
}

// createUser adds an administrator and returns the authenticator secret and
// recovery codes exactly once, matching the first-run flow.
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in userBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if in.Username == "" || len(in.Username) > 64 {
		writeError(w, http.StatusBadRequest, "a username of 1–64 characters is required")
		return
	}
	if _, err := s.db(r).RoleByID(in.RoleID); err != nil {
		writeError(w, http.StatusBadRequest, "choose a valid role")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot generate authenticator secret")
		return
	}
	codes, stored, err := auth.NewRecoveryCodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot generate recovery codes")
		return
	}
	sealedSecret, err := s.box.Seal(secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encryption error")
		return
	}
	sealedCodes, err := s.box.Seal(stored)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encryption error")
		return
	}
	id, err := s.db(r).CreateUserWithRole(in.Username, hash, sealedSecret, sealedCodes, true, in.RoleID)
	if err != nil {
		writeError(w, http.StatusConflict, "username already exists")
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "user.create", in.Username, clientIP(r))
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "username": in.Username, "totp_secret": secret,
		"otpauth_url":    auth.OTPAuthURL("WAF-Proxy", in.Username, secret),
		"recovery_codes": codes,
	})
}

type userUpdateBody struct {
	RoleID   *int64 `json:"role_id"`
	Password string `json:"password"`
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in userUpdateBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	target, err := s.db(r).UserByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	sess := sessionFrom(r)
	if in.RoleID != nil {
		role, err := s.db(r).RoleByID(*in.RoleID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "choose a valid role")
			return
		}
		// Demoting the last administrator would leave nobody able to manage
		// accounts and system settings.
		if role.Name != rbac.Administrator && target.RoleID == s.db(r).AdminRoleID() {
			admins, err := s.db(r).AdministratorCount()
			if err != nil {
				writeError(w, http.StatusInternalServerError, "database error")
				return
			}
			if admins <= 1 {
				writeError(w, http.StatusConflict, "this is the last administrator; promote another account first")
				return
			}
		}
		if target.ID == sess.UserID && role.Name != rbac.Administrator {
			writeError(w, http.StatusConflict, "you cannot remove your own administrator role")
			return
		}
		if err := s.db(r).UpdateUserRole(id, role.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "cannot update role")
			return
		}
	}
	if in.Password != "" {
		hash, err := auth.HashPassword(in.Password)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.db(r).UpdateUserPassword(id, hash); err != nil {
			writeError(w, http.StatusInternalServerError, "cannot update password")
			return
		}
		_ = s.db(r).DeleteUserSessions(id)
	}
	s.db(r).AddAudit(sess.Username, "user.update", target.Username, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	target, err := s.db(r).UserByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	sess := sessionFrom(r)
	if target.ID == sess.UserID {
		writeError(w, http.StatusConflict, "you cannot delete the account you are signed in with")
		return
	}
	if target.RoleID == s.db(r).AdminRoleID() {
		admins, err := s.db(r).AdministratorCount()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		if admins <= 1 {
			writeError(w, http.StatusConflict, "the last administrator cannot be deleted")
			return
		}
	}
	if err := s.db(r).DeleteUser(id); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot delete account")
		return
	}
	s.db(r).AddAudit(sess.Username, "user.delete", target.Username, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.db(r).ListRoles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles, "areas": rbac.Areas})
}

type roleBody struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

func (s *Server) createRole(w http.ResponseWriter, r *http.Request) {
	var in roleBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	role, msg := cleanRole(roleBody{Name: in.Name, Description: in.Description, Permissions: in.Permissions})
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if err := s.db(r).CreateRole(role); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			writeError(w, http.StatusConflict, "a role with that name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "cannot create role")
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "role.create", role.Name, clientIP(r))
	writeJSON(w, http.StatusCreated, role)
}

func (s *Server) updateRole(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	current, err := s.db(r).RoleByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if current.Builtin {
		writeError(w, http.StatusConflict, "built-in roles cannot be edited")
		return
	}
	var in roleBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	role, msg := cleanRole(in)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	role.ID = id
	if err := s.db(r).UpdateRole(role); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			writeError(w, http.StatusConflict, "a role with that name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "cannot update role")
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "role.update", role.Name, clientIP(r))
	writeJSON(w, http.StatusOK, role)
}

func (s *Server) deleteRole(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	role, err := s.db(r).RoleByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if role.Builtin {
		writeError(w, http.StatusConflict, "built-in roles cannot be deleted")
		return
	}
	if err := s.db(r).DeleteRole(id); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			writeError(w, http.StatusConflict, "this role is assigned to an account; move the account first")
			return
		}
		writeError(w, http.StatusInternalServerError, "cannot delete role")
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "role.delete", role.Name, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// pathID parses the {id} path value shared by the account endpoints.
func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid id")
		return 0, false
	}
	return id, true
}

func cleanRole(in roleBody) (*model.Role, string) {
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 64 {
		return nil, "a role name of 1–64 characters is required"
	}
	perms := rbac.Normalize(in.Permissions)
	if len(perms) == 0 {
		return nil, "choose at least one permission"
	}
	for _, p := range in.Permissions {
		if !rbac.Valid(strings.TrimSpace(p)) {
			return nil, "unknown permission: " + p
		}
	}
	return &model.Role{Name: name, Description: strings.TrimSpace(in.Description), Permissions: perms}, ""
}
