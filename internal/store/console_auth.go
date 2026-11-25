package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

const consoleAuthColumns = `id, kind, enabled, host, port, secret, base_dn, bind_dn, bind_password,
	user_filter, group_filter, email_attr, use_tls, start_tls, skip_verify, timeout_seconds,
	default_role_id, role_map, created_at`

func scanConsoleAuth(row interface{ Scan(...any) error }) (*model.ConsoleAuth, error) {
	var p model.ConsoleAuth
	var enabled, useTLS, startTLS, skipVerify int
	var created string
	err := row.Scan(&p.ID, &p.Kind, &enabled, &p.Host, &p.Port, &p.Secret, &p.BaseDN, &p.BindDN,
		&p.BindPassword, &p.UserFilter, &p.GroupFilter, &p.EmailAttr, &useTLS, &startTLS, &skipVerify,
		&p.TimeoutSeconds, &p.DefaultRoleID, &p.RoleMap, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.Enabled = i2b(enabled)
	p.UseTLS = i2b(useTLS)
	p.StartTLS = i2b(startTLS)
	p.SkipVerify = i2b(skipVerify)
	p.HasSecret = p.Secret != ""
	p.HasBindPassword = p.BindPassword != ""
	p.CreatedAt = parseStamp(created)
	return &p, nil
}

// ListConsoleAuth returns the configured console directory providers.
func (s *Store) ListConsoleAuth() ([]model.ConsoleAuth, error) {
	rows, err := s.db.Query(`SELECT `+consoleAuthColumns+` FROM console_auth WHERE site_id = ? ORDER BY kind`, s.site)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ConsoleAuth{}
	for rows.Next() {
		p, err := scanConsoleAuth(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// GetConsoleAuth loads one kind of console directory.
func (s *Store) GetConsoleAuth(kind string) (*model.ConsoleAuth, error) {
	return scanConsoleAuth(s.db.QueryRow(`SELECT `+consoleAuthColumns+` FROM console_auth WHERE kind = ? AND site_id = ?`, kind, s.site))
}

// SaveConsoleAuth inserts or updates the one row for this site and kind.
func (s *Store) SaveConsoleAuth(p *model.ConsoleAuth) error {
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	_, err := s.db.Exec(`INSERT INTO console_auth(kind, enabled, host, port, secret, base_dn, bind_dn,
		bind_password, user_filter, group_filter, email_attr, use_tls, start_tls, skip_verify,
		timeout_seconds, default_role_id, role_map, created_at, site_id)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(site_id, kind) DO UPDATE SET enabled = excluded.enabled, host = excluded.host,
		port = excluded.port, secret = excluded.secret, base_dn = excluded.base_dn,
		bind_dn = excluded.bind_dn, bind_password = excluded.bind_password,
		user_filter = excluded.user_filter, group_filter = excluded.group_filter,
		email_attr = excluded.email_attr, use_tls = excluded.use_tls, start_tls = excluded.start_tls,
		skip_verify = excluded.skip_verify, timeout_seconds = excluded.timeout_seconds,
		default_role_id = excluded.default_role_id, role_map = excluded.role_map`,
		p.Kind, b2i(p.Enabled), p.Host, p.Port, p.Secret, p.BaseDN, p.BindDN, p.BindPassword,
		p.UserFilter, p.GroupFilter, p.EmailAttr, b2i(p.UseTLS), b2i(p.StartTLS), b2i(p.SkipVerify),
		p.TimeoutSeconds, p.DefaultRoleID, p.RoleMap, stamp(p.CreatedAt), s.site)
	return err
}

// UpsertExternalUser creates the local shadow account for a directory sign-in,
// or refreshes its role and email. It never takes over a local password
// account, so a directory cannot shadow a local administrator.
func (s *Store) UpsertExternalUser(username, email, source string, roleID int64) (*User, error) {
	user, err := s.UserByUsername(username)
	switch {
	case err == nil:
		if user.AuthSource == "" || user.AuthSource == "local" {
			return nil, errors.New("a local account already uses that username")
		}
		// Keep an address the administrator set in Account when the directory
		// does not return one; a blank directory value must not erase it.
		if _, err := s.db.Exec(`UPDATE users SET email = CASE WHEN ? <> '' THEN ? ELSE email END,
			role_id = ?, auth_source = ? WHERE id = ? AND (? = 0 OR site_id = ?)`,
			email, email, roleID, source, user.ID, s.site, s.site); err != nil {
			return nil, err
		}
		return s.UserByID(user.ID)
	case !errors.Is(err, ErrNotFound):
		return nil, err
	}
	_, err = s.db.Exec(`INSERT INTO users(username, email, password_hash, totp_secret, totp_enabled,
		recovery_codes, role_id, auth_source, created_at, site_id)
		VALUES(?, ?, '', '', 0, '', ?, ?, ?, ?)`,
		username, email, roleID, source, stamp(time.Now()), s.site)
	if err != nil {
		return nil, err
	}
	return s.UserByUsername(username)
}
