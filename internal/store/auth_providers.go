package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

const authProviderColumns = `id, name, kind, verify_url, login_url, header, secret`

func scanAuthProvider(row interface{ Scan(...any) error }) (*model.AuthProvider, error) {
	var p model.AuthProvider
	err := row.Scan(&p.ID, &p.Name, &p.Kind, &p.VerifyURL, &p.LoginURL, &p.Header, &p.Secret)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.HasSecret = p.Secret != ""
	return &p, nil
}

// ListAuthProviders returns the configured forward-auth providers.
func (s *Store) ListAuthProviders() ([]model.AuthProvider, error) {
	rows, err := s.db.Query(`SELECT `+authProviderColumns+` FROM auth_providers WHERE (? = 0 OR site_id = ?) ORDER BY name`, s.site, s.site)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AuthProvider{}
	for rows.Next() {
		p, err := scanAuthProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// GetAuthProvider loads one provider.
func (s *Store) GetAuthProvider(id int64) (*model.AuthProvider, error) {
	return scanAuthProvider(s.db.QueryRow(`SELECT `+authProviderColumns+` FROM auth_providers WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site))
}

// CreateAuthProvider inserts a provider and returns its ID.
func (s *Store) CreateAuthProvider(p *model.AuthProvider) (int64, error) {
	var exists int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM auth_providers WHERE name = ?`, p.Name).Scan(&exists); err != nil {
		return 0, err
	}
	if exists > 0 {
		return 0, ErrDuplicate
	}
	res, err := s.db.Exec(`INSERT INTO auth_providers(name, kind, verify_url, login_url, header, secret, created_at, site_id)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.Kind, p.VerifyURL, p.LoginURL, p.Header, p.Secret, stamp(time.Now()), s.site)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateAuthProvider writes the mutable fields of a provider.
func (s *Store) UpdateAuthProvider(p *model.AuthProvider) error {
	var exists int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM auth_providers WHERE name = ? AND id <> ?`, p.Name, p.ID).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return ErrDuplicate
	}
	_, err := s.db.Exec(`UPDATE auth_providers SET name = ?, kind = ?, verify_url = ?, login_url = ?,
		header = ?, secret = ? WHERE id = ? AND (? = 0 OR site_id = ?)`,
		p.Name, p.Kind, p.VerifyURL, p.LoginURL, p.Header, p.Secret, p.ID, s.site, s.site)
	return err
}

// DeleteAuthProvider removes a provider that no proxy uses. A proxy left on
// forward_auth without its provider would fail closed on every request, so the
// caller must detach it first.
func (s *Store) DeleteAuthProvider(id int64) (bool, error) {
	var used int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM proxies WHERE auth_provider_id = ?`, id).Scan(&used); err != nil {
		return false, err
	}
	if used > 0 {
		return true, nil
	}
	_, err := s.db.Exec(`DELETE FROM auth_providers WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site)
	return false, err
}
