// Package consoleauth authenticates administrators against external directory
// services. It returns directory attributes; the API maps those to console
// roles and owns account provisioning.
package consoleauth

import (
	"context"
	"errors"
	"fmt"
)

// Config is one console directory. Secrets are decrypted by the caller only
// for the duration of a sign-in attempt.
type Config struct {
	Kind           string
	Host           string
	Port           int
	Secret         string
	BaseDN         string
	BindDN         string
	BindPassword   string
	UserFilter     string
	GroupFilter    string
	EmailAttr      string
	UseTLS         bool
	StartTLS       bool
	SkipVerify     bool
	TimeoutSeconds int
}

// Result is a successful directory sign-in. RoleHint is a TACACS+ role or
// privilege argument; Groups are LDAP group DNs and names. Either is matched
// against the provider's role map.
type Result struct {
	Email    string
	RoleHint string
	Groups   []string
	// Warning records a non-fatal directory detail, such as an LDAP group
	// search that failed after the bind succeeded.
	Warning string
}

// ErrInvalidCredentials means the directory answered and refused the password.
// Transport and configuration failures use other errors so the login page can
// keep the public message generic while the audit log keeps the detail.
var ErrInvalidCredentials = errors.New("invalid credentials")

// ErrAuthorizationDenied means the directory accepted the password but refused
// shell authorization. ErrDirectoryUnavailable means that authorization could
// not be reached. Both deny the console sign-in instead of granting a default
// role, and both stop a multi-directory login from falling through.
var (
	ErrAuthorizationDenied  = errors.New("directory authorization denied")
	ErrDirectoryUnavailable = errors.New("directory authorization unavailable")
)

// Authenticate dispatches to one protocol. Every implementation uses the
// configured timeout and returns ErrInvalidCredentials only for a definite
// refusal.
func Authenticate(ctx context.Context, cfg Config, username, password string) (Result, error) {
	if username == "" || password == "" {
		return Result{}, ErrInvalidCredentials
	}
	if cfg.Kind == "tacacs" && (len(username) > 255 || len(password) > 255) {
		return Result{}, ErrInvalidCredentials
	}
	if cfg.Kind == "radius" && (len(username) > 253 || len(password) > 128) {
		return Result{}, ErrInvalidCredentials
	}
	switch cfg.Kind {
	case "tacacs":
		return authenticateTACACS(ctx, cfg, username, password)
	case "radius":
		return authenticateRADIUS(ctx, cfg, username, password)
	case "ldap":
		return authenticateLDAP(ctx, cfg, username, password)
	default:
		return Result{}, fmt.Errorf("unknown console directory %q", cfg.Kind)
	}
}
