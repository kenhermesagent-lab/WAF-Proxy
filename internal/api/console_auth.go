package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/consoleauth"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

var consoleAuthKinds = map[string]string{
	"tacacs": "TACACS+",
	"radius": "RADIUS",
	"ldap":   "LDAP/AD",
}

var ldapAttrRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)

type consoleAuthBody struct {
	Enabled        bool   `json:"enabled"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Secret         string `json:"secret"`
	BaseDN         string `json:"base_dn"`
	BindDN         string `json:"bind_dn"`
	BindPassword   string `json:"bind_password"`
	UserFilter     string `json:"user_filter"`
	GroupFilter    string `json:"group_filter"`
	EmailAttr      string `json:"email_attr"`
	UseTLS         bool   `json:"use_tls"`
	StartTLS       bool   `json:"start_tls"`
	SkipVerify     bool   `json:"skip_verify"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	DefaultRoleID  int64  `json:"default_role_id"`
	RoleMap        string `json:"role_map"`
}

func defaultConsolePort(kind string) int {
	switch kind {
	case "tacacs":
		return 49
	case "radius":
		return 1812
	default:
		return 389
	}
}

func (in consoleAuthBody) apply(p *model.ConsoleAuth, kind string) {
	p.Kind = kind
	p.Enabled = in.Enabled
	p.Host = strings.TrimSpace(in.Host)
	p.Port = in.Port
	if p.Port == 0 {
		p.Port = defaultConsolePort(kind)
	}
	p.BaseDN = strings.TrimSpace(in.BaseDN)
	p.BindDN = strings.TrimSpace(in.BindDN)
	p.UserFilter = strings.TrimSpace(in.UserFilter)
	p.GroupFilter = strings.TrimSpace(in.GroupFilter)
	p.EmailAttr = strings.TrimSpace(in.EmailAttr)
	if p.EmailAttr == "" {
		p.EmailAttr = "mail"
	}
	p.UseTLS = in.UseTLS
	p.StartTLS = in.StartTLS
	p.SkipVerify = in.SkipVerify
	p.TimeoutSeconds = in.TimeoutSeconds
	if p.TimeoutSeconds == 0 {
		p.TimeoutSeconds = 8
	}
	p.DefaultRoleID = in.DefaultRoleID
	p.RoleMap = strings.TrimSpace(in.RoleMap)
	if kind == "ldap" && p.UserFilter == "" {
		p.UserFilter = "(uid={username})"
	}
}

func validConsoleAuthHost(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/\\@ ") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	return regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$`).MatchString(host) &&
		!strings.Contains(host, "..")
}

func parseRoleMap(raw string) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndex(line, "=")
		if i <= 0 || i == len(line)-1 {
			return nil, fmt.Errorf("role map line %q must be match=Role", line)
		}
		key := strings.TrimSpace(line[:i])
		role := strings.TrimSpace(line[i+1:])
		if key == "" || role == "" {
			return nil, fmt.Errorf("role map line %q must be match=Role", line)
		}
		out[strings.ToLower(key)] = role
	}
	return out, nil
}

func (s *Server) validateConsoleAuth(p *model.ConsoleAuth) string {
	if consoleAuthKinds[p.Kind] == "" {
		return "unknown console directory"
	}
	if p.Enabled || p.Host != "" {
		if !validConsoleAuthHost(p.Host) {
			return "the server host must be a hostname or IP address"
		}
		if p.Port < 1 || p.Port > 65535 {
			return "the port must be between 1 and 65535"
		}
	}
	if p.TimeoutSeconds < 1 || p.TimeoutSeconds > 60 {
		return "the timeout must be between 1 and 60 seconds"
	}
	if p.DefaultRoleID != 0 {
		if _, err := s.st.RoleByID(p.DefaultRoleID); err != nil {
			return "the default role no longer exists"
		}
	}
	mapping, err := parseRoleMap(p.RoleMap)
	if err != nil {
		return err.Error()
	}
	if len(mapping) > 0 {
		roles, err := s.st.ListRoles()
		if err != nil {
			return "cannot read roles"
		}
		known := map[string]bool{}
		for _, role := range roles {
			known[strings.ToLower(role.Name)] = true
		}
		for key, roleName := range mapping {
			if !known[strings.ToLower(roleName)] {
				return fmt.Sprintf("role map entry %q names an unknown role %q", key, roleName)
			}
		}
	}
	if !p.Enabled {
		return ""
	}
	if p.Host == "" {
		return "the server host is required"
	}
	switch p.Kind {
	case "tacacs", "radius":
		if p.Secret == "" {
			return "a shared secret is required"
		}
		if p.Kind == "radius" && p.DefaultRoleID == 0 {
			return "RADIUS authenticates only, so choose the role its administrators receive"
		}
	case "ldap":
		if p.BaseDN == "" {
			return "a base DN is required"
		}
		if !strings.Contains(p.UserFilter, "{username}") {
			return "the user filter must contain {username}"
		}
		if !ldapAttrRE.MatchString(p.EmailAttr) {
			return "the email attribute must be an LDAP attribute name"
		}
		if (p.BindDN == "") != (p.BindPassword == "") {
			return "the bind DN and bind password must both be set, or both be empty"
		}
	}
	return ""
}

func publicConsoleAuth(p *model.ConsoleAuth) model.ConsoleAuth {
	out := *p
	out.Secret = ""
	out.BindPassword = ""
	out.HasSecret = p.Secret != ""
	out.HasBindPassword = p.BindPassword != ""
	return out
}

func (s *Server) listConsoleAuth(w http.ResponseWriter, r *http.Request) {
	list, err := s.db(r).ListConsoleAuth()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	out := make([]model.ConsoleAuth, 0, len(list))
	for i := range list {
		out = append(out, publicConsoleAuth(&list[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func consoleKind(path string) string {
	kind := strings.TrimPrefix(path, "/api/console-auth/")
	kind = strings.TrimSuffix(kind, "/test")
	return strings.Trim(kind, "/")
}

func (s *Server) putConsoleAuth(w http.ResponseWriter, r *http.Request) {
	kind := consoleKind(r.URL.Path)
	if consoleAuthKinds[kind] == "" {
		writeError(w, http.StatusNotFound, "unknown console directory")
		return
	}
	var in consoleAuthBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	current, err := s.db(r).GetConsoleAuth(kind)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if current == nil {
		current = &model.ConsoleAuth{Kind: kind}
	}
	// An empty secret keeps the stored one; the sealed value never reaches the
	// browser, so clearing a secret takes a rotation, not an accidental blank.
	in.apply(current, kind)
	if in.Secret != "" {
		sealed, err := s.box.Seal(in.Secret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encryption error")
			return
		}
		current.Secret = sealed
	}
	if in.BindPassword != "" {
		sealed, err := s.box.Seal(in.BindPassword)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encryption error")
			return
		}
		current.BindPassword = sealed
	}
	if msg := s.validateConsoleAuth(current); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if err := s.db(r).SaveConsoleAuth(current); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "console-auth.update", kind, clientIP(r))
	writeJSON(w, http.StatusOK, publicConsoleAuth(current))
}

func (s *Server) deleteConsoleAuth(w http.ResponseWriter, r *http.Request) {
	kind := consoleKind(r.URL.Path)
	current, err := s.db(r).GetConsoleAuth(kind)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	current.Enabled = false
	if err := s.db(r).SaveConsoleAuth(current); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "console-auth.disable", kind, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) consoleAuthConfig(p *model.ConsoleAuth) (consoleauth.Config, error) {
	cfg := consoleauth.Config{
		Kind: p.Kind, Host: p.Host, Port: p.Port, BaseDN: p.BaseDN, BindDN: p.BindDN,
		UserFilter: p.UserFilter, GroupFilter: p.GroupFilter, EmailAttr: p.EmailAttr,
		UseTLS: p.UseTLS, StartTLS: p.StartTLS, SkipVerify: p.SkipVerify,
		TimeoutSeconds: p.TimeoutSeconds,
	}
	if p.Secret != "" {
		v, err := s.box.Open(p.Secret)
		if err != nil {
			return cfg, fmt.Errorf("cannot decrypt shared secret")
		}
		cfg.Secret = v
	}
	if p.BindPassword != "" {
		v, err := s.box.Open(p.BindPassword)
		if err != nil {
			return cfg, fmt.Errorf("cannot decrypt bind password")
		}
		cfg.BindPassword = v
	}
	return cfg, nil
}

func (s *Server) testConsoleAuth(w http.ResponseWriter, r *http.Request) {
	kind := consoleKind(r.URL.Path)
	if consoleAuthKinds[kind] == "" {
		writeError(w, http.StatusNotFound, "unknown console directory")
		return
	}
	if !s.limiter.Allow("console-auth-test:"+clientIP(r), 10, time.Minute) {
		writeError(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &in); err != nil || in.Username == "" || in.Password == "" {
		writeError(w, http.StatusBadRequest, "a username and password are required")
		return
	}
	p, err := s.db(r).GetConsoleAuth(kind)
	if err != nil {
		writeError(w, http.StatusNotFound, "this directory is not configured yet")
		return
	}
	cfg, err := s.consoleAuthConfig(p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(max(p.TimeoutSeconds, 8))*time.Second)
	defer cancel()
	res, err := consoleauth.Authenticate(ctx, cfg, in.Username, in.Password)
	if err != nil {
		if errors.Is(err, consoleauth.ErrInvalidCredentials) {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "the directory rejected those credentials"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	roleID, roleName, warning := s.roleForExternal(p, res)
	body := map[string]any{
		"ok": true, "message": "the directory accepted the sign-in", "email": res.Email,
		"groups": res.Groups,
	}
	if warning != "" {
		body["warning"] = warning
	}
	if roleID != 0 {
		body["role"] = roleName
	} else {
		body["warning"] = "signed in, but no role matched and no default role is set"
	}
	writeJSON(w, http.StatusOK, body)
}

// roleForExternal maps the directory's role or group attributes to a console
// role. A default role is the fallback; zero means the sign-in has no access.
func (s *Server) roleForExternal(p *model.ConsoleAuth, res consoleauth.Result) (int64, string, string) {
	mapping, _ := parseRoleMap(p.RoleMap)
	roles, _ := s.st.ListRoles()
	byName := map[string]model.Role{}
	for _, role := range roles {
		byName[strings.ToLower(role.Name)] = role
	}
	candidates := []string{}
	if res.RoleHint != "" {
		candidates = append(candidates, res.RoleHint, "role="+res.RoleHint, "priv-lvl="+res.RoleHint)
	}
	for _, g := range res.Groups {
		candidates = append(candidates, g)
		// A TACACS AV pair can be mapped either whole or by value.
		if _, value, ok := strings.Cut(g, "="); ok {
			candidates = append(candidates, value)
		}
	}
	for _, c := range candidates {
		if roleName, ok := mapping[strings.ToLower(strings.TrimSpace(c))]; ok {
			if role, ok := byName[strings.ToLower(roleName)]; ok {
				return role.ID, role.Name, res.Warning
			}
		}
	}
	if p.DefaultRoleID != 0 {
		if role, err := s.st.RoleByID(p.DefaultRoleID); err == nil {
			return role.ID, role.Name, res.Warning
		}
	}
	if res.Warning != "" {
		return 0, "", res.Warning
	}
	return 0, "", "no role matched and no default role is set"
}

// externalLogin authenticates one administrator against the enabled console
// directories. source pins the provider for an account that already came from a
// directory; an unknown username may match any enabled provider.
func (s *Server) externalLogin(r *http.Request, ctx context.Context, username, password, source string) (*store.User, string, error) {
	kinds := []string{"tacacs", "radius", "ldap"}
	if source != "" && source != "local" {
		kinds = []string{source}
	}
	var lastErr error
	for _, kind := range kinds {
		p, err := s.db(r).GetConsoleAuth(kind)
		if err != nil || p == nil || !p.Enabled {
			continue
		}
		cfg, err := s.consoleAuthConfig(p)
		if err != nil {
			lastErr = err
			continue
		}
		timeout := time.Duration(max(p.TimeoutSeconds, 8)) * time.Second
		cctx, cancel := context.WithTimeout(ctx, timeout)
		res, err := consoleauth.Authenticate(cctx, cfg, username, password)
		cancel()
		if err != nil {
			// A directory that accepted the password but refused authorization,
			// or could not answer the authorization check, ends the attempt. Do
			// not let another directory grant the role this one withheld.
			if errors.Is(err, consoleauth.ErrAuthorizationDenied) || errors.Is(err, consoleauth.ErrDirectoryUnavailable) {
				return nil, "", err
			}
			lastErr = err
			continue
		}
		roleID, roleName, warning := s.roleForExternal(p, res)
		if roleID == 0 {
			return nil, "", fmt.Errorf("%s signed in but no console role was assigned: %s", consoleAuthKinds[kind], warning)
		}
		user, err := s.db(r).UpsertExternalUser(username, res.Email, kind, roleID)
		if err != nil {
			return nil, "", err
		}
		detail := consoleAuthKinds[kind] + " role " + roleName
		if warning != "" {
			detail += " (" + warning + ")"
		}
		return user, detail, nil
	}
	if lastErr != nil {
		return nil, "", lastErr
	}
	return nil, "", consoleauth.ErrInvalidCredentials
}
