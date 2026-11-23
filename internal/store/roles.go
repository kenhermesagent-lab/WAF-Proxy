package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/rbac"
)

// seedRoles creates the built-in roles and gives every account that predates
// RBAC the Administrator role, so an upgrade never removes access.
func (s *Store) seedRoles() error {
	for _, role := range rbac.Builtins() {
		_, err := s.db.Exec(`INSERT INTO roles(name, description, builtin, permissions)
			VALUES(?, ?, 1, ?)
			ON CONFLICT(name) DO UPDATE SET description = excluded.description, permissions = excluded.permissions
			WHERE roles.builtin = 1`,
			role.Name, role.Description, rbac.Join(role.Permissions))
		if err != nil {
			return fmt.Errorf("seed role %s: %w", role.Name, err)
		}
	}
	_, err := s.db.Exec(`UPDATE users SET role_id = ? WHERE role_id = 0`, s.AdminRoleID())
	return err
}

// AdminRoleID returns the built-in Administrator role's ID (0 when the roles
// table has not been seeded yet).
func (s *Store) AdminRoleID() int64 {
	var id int64
	_ = s.db.QueryRow(`SELECT id FROM roles WHERE name = ?`, rbac.Administrator).Scan(&id)
	return id
}

func scanRole(row interface{ Scan(...any) error }) (*model.Role, error) {
	var r model.Role
	var builtin int
	var perms string
	err := row.Scan(&r.ID, &r.Name, &r.Description, &builtin, &perms)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Builtin = i2b(builtin)
	r.Permissions = rbac.Parse(perms)
	return &r, nil
}

// ListRoles returns every role, built-ins first.
func (s *Store) ListRoles() ([]model.Role, error) {
	rows, err := s.db.Query(`SELECT id, name, description, builtin, permissions FROM roles ORDER BY builtin DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Role{}
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// RoleByID loads one role.
func (s *Store) RoleByID(id int64) (*model.Role, error) {
	return scanRole(s.db.QueryRow(`SELECT id, name, description, builtin, permissions FROM roles WHERE id = ?`, id))
}

// CreateRole inserts a custom role.
func (s *Store) CreateRole(r *model.Role) error {
	res, err := s.db.Exec(`INSERT INTO roles(name, description, builtin, permissions) VALUES(?, ?, 0, ?)`,
		r.Name, r.Description, rbac.Join(r.Permissions))
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicate
		}
		return err
	}
	r.ID, _ = res.LastInsertId()
	r.Builtin = false
	r.Permissions = rbac.Normalize(r.Permissions)
	return nil
}

// UpdateRole replaces a custom role's name, description and permissions.
func (s *Store) UpdateRole(r *model.Role) error {
	res, err := s.db.Exec(`UPDATE roles SET name = ?, description = ?, permissions = ? WHERE id = ? AND builtin = 0`,
		r.Name, r.Description, rbac.Join(r.Permissions), r.ID)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicate
		}
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	r.Permissions = rbac.Normalize(r.Permissions)
	return nil
}

// RoleInUse counts the accounts assigned to a role.
func (s *Store) RoleInUse(id int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role_id = ?`, id).Scan(&n)
	return n, err
}

// DeleteRole removes a custom role that no account uses.
func (s *Store) DeleteRole(id int64) error {
	inUse, err := s.RoleInUse(id)
	if err != nil {
		return err
	}
	if inUse > 0 {
		return fmt.Errorf("%w: role is assigned to %d account(s)", ErrDuplicate, inUse)
	}
	res, err := s.db.Exec(`DELETE FROM roles WHERE id = ? AND builtin = 0`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// AdministratorCount counts accounts holding the Administrator role.
func (s *Store) AdministratorCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users u JOIN roles r ON r.id = u.role_id
		WHERE r.name = ? AND (? = 0 OR u.site_id = ?)`, rbac.Administrator, s.site, s.site).Scan(&n)
	return n, err
}

// UserSummary is an account row shown in the console.
type UserSummary struct {
	ID          int64     `json:"id"`
	Username    string    `json:"username"`
	RoleID      int64     `json:"role_id"`
	Role        string    `json:"role"`
	TOTPEnabled bool      `json:"totp_enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

// ListUsers returns every administrator account with its role name.
func (s *Store) ListUsers() ([]UserSummary, error) {
	rows, err := s.db.Query(`SELECT u.id, u.username, u.role_id, COALESCE(r.name, ''),
		u.totp_enabled, u.created_at
		FROM users u LEFT JOIN roles r ON r.id = u.role_id
		WHERE (? = 0 OR u.site_id = ?) ORDER BY u.id`, s.site, s.site)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UserSummary{}
	for rows.Next() {
		var u UserSummary
		var totp int
		var created string
		if err := rows.Scan(&u.ID, &u.Username, &u.RoleID, &u.Role, &totp, &created); err != nil {
			return nil, err
		}
		u.TOTPEnabled = i2b(totp)
		u.CreatedAt = parseStamp(created)
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUserRole changes which role an account holds.
func (s *Store) UpdateUserRole(id, roleID int64) error {
	res, err := s.db.Exec(`UPDATE users SET role_id = ? WHERE id = ?`, roleID, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteUser removes an administrator and their sessions.
func (s *Store) DeleteUser(id int64) error {
	if _, err := s.db.Exec(`DELETE FROM users WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site); err != nil {
		return err
	}
	return nil
}

// isUniqueViolation matches SQLite's UNIQUE constraint error text without
// pulling in a driver-specific error type.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") || strings.Contains(msg, "constraint failed: UNIQUE")
}
