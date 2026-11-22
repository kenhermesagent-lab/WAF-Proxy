package store

import (
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

const protectionProfileColumns = `id, name, builtin, force_https, hsts, hsts_subdomains,
	frame_options, nosniff, referrer_policy, csp, permissions_policy, hide_server`

func scanProtectionProfile(row interface{ Scan(...any) error }) (*model.ProtectionProfile, error) {
	var p model.ProtectionProfile
	var builtin, forceHTTPS, hsts, hstsSub, nosniff, hideServer int
	err := row.Scan(&p.ID, &p.Name, &builtin, &forceHTTPS, &hsts, &hstsSub,
		&p.FrameOptions, &nosniff, &p.ReferrerPolicy, &p.CSP, &p.PermissionsPolicy, &hideServer)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.Builtin = i2b(builtin)
	p.ForceHTTPS = i2b(forceHTTPS)
	p.HSTS = i2b(hsts)
	p.HSTSSubdomains = i2b(hstsSub)
	p.NoSniff = i2b(nosniff)
	p.HideServer = i2b(hideServer)
	return &p, nil
}

// ListProtectionProfiles returns the response-hardening profiles.
func (s *Store) ListProtectionProfiles() ([]model.ProtectionProfile, error) {
	rows, err := s.db.Query(`SELECT ` + protectionProfileColumns + ` FROM protection_profiles ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ProtectionProfile{}
	for rows.Next() {
		p, err := scanProtectionProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// GetProtectionProfile loads one profile.
func (s *Store) GetProtectionProfile(id int64) (*model.ProtectionProfile, error) {
	row := s.db.QueryRow(`SELECT `+protectionProfileColumns+` FROM protection_profiles WHERE id = ?`, id)
	return scanProtectionProfile(row)
}

// CreateProtectionProfile inserts an operator-defined profile.
func (s *Store) CreateProtectionProfile(p *model.ProtectionProfile) error {
	var exists int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM protection_profiles WHERE name = ?`, p.Name).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return ErrDuplicate
	}
	res, err := s.db.Exec(`INSERT INTO protection_profiles(name, builtin, force_https, hsts, hsts_subdomains,
		frame_options, nosniff, referrer_policy, csp, permissions_policy, hide_server)
		VALUES(?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, b2i(p.ForceHTTPS), b2i(p.HSTS), b2i(p.HSTSSubdomains), p.FrameOptions,
		b2i(p.NoSniff), p.ReferrerPolicy, p.CSP, p.PermissionsPolicy, b2i(p.HideServer))
	if err != nil {
		return err
	}
	p.ID, err = res.LastInsertId()
	return err
}

// UpdateProtectionProfile writes every tunable field. The name is immutable so
// a proxy keeps pointing at a profile an operator recognises.
func (s *Store) UpdateProtectionProfile(p *model.ProtectionProfile) error {
	_, err := s.db.Exec(`UPDATE protection_profiles SET force_https = ?, hsts = ?, hsts_subdomains = ?,
		frame_options = ?, nosniff = ?, referrer_policy = ?, csp = ?, permissions_policy = ?, hide_server = ?
		WHERE id = ?`,
		b2i(p.ForceHTTPS), b2i(p.HSTS), b2i(p.HSTSSubdomains), p.FrameOptions, b2i(p.NoSniff),
		p.ReferrerPolicy, p.CSP, p.PermissionsPolicy, b2i(p.HideServer), p.ID)
	return err
}

// ProtectionProfileInUse counts the proxies selecting a profile.
func (s *Store) ProtectionProfileInUse(id int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM proxies WHERE protection_profile_id = ?`, id).Scan(&n)
	return n, err
}

// DeleteProtectionProfile removes an operator-defined profile.
func (s *Store) DeleteProtectionProfile(id int64) error {
	_, err := s.db.Exec(`DELETE FROM protection_profiles WHERE id = ? AND builtin = 0`, id)
	return err
}

func (s *Store) seedProtectionProfiles() error {
	_, err := s.db.Exec(`INSERT INTO protection_profiles(name, builtin, force_https, hsts, hsts_subdomains,
		frame_options, nosniff, referrer_policy, hide_server)
		VALUES('Recommended hardening', 1, 1, 1, 1, 'sameorigin', 1, 'strict-origin-when-cross-origin', 1)
		ON CONFLICT(name) DO NOTHING`)
	return err
}

// ListAccessProfiles returns the named policy bundles.
func (s *Store) ListAccessProfiles() ([]model.AccessProfile, error) {
	rows, err := s.db.Query(`SELECT id, name, policy_ids FROM access_profiles ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AccessProfile{}
	for rows.Next() {
		var a model.AccessProfile
		var ids string
		if err := rows.Scan(&a.ID, &a.Name, &ids); err != nil {
			return nil, err
		}
		a.PolicyIDs = parseIDList(ids)
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetAccessProfile loads one bundle.
func (s *Store) GetAccessProfile(id int64) (*model.AccessProfile, error) {
	var a model.AccessProfile
	var ids string
	err := s.db.QueryRow(`SELECT id, name, policy_ids FROM access_profiles WHERE id = ?`, id).
		Scan(&a.ID, &a.Name, &ids)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.PolicyIDs = parseIDList(ids)
	return &a, nil
}

// CreateAccessProfile inserts a bundle.
func (s *Store) CreateAccessProfile(a *model.AccessProfile) error {
	var exists int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM access_profiles WHERE name = ?`, a.Name).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return ErrDuplicate
	}
	res, err := s.db.Exec(`INSERT INTO access_profiles(name, policy_ids) VALUES(?, ?)`,
		a.Name, joinIDList(a.PolicyIDs))
	if err != nil {
		return err
	}
	a.ID, err = res.LastInsertId()
	return err
}

// UpdateAccessProfile replaces a bundle's policy selection.
func (s *Store) UpdateAccessProfile(a *model.AccessProfile) error {
	_, err := s.db.Exec(`UPDATE access_profiles SET policy_ids = ? WHERE id = ?`, joinIDList(a.PolicyIDs), a.ID)
	return err
}

// AccessProfileInUse counts the proxies selecting a bundle.
func (s *Store) AccessProfileInUse(id int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM proxies WHERE access_profile_id = ?`, id).Scan(&n)
	return n, err
}

// DeleteAccessProfile removes a bundle. The policies themselves are untouched.
func (s *Store) DeleteAccessProfile(id int64) error {
	_, err := s.db.Exec(`DELETE FROM access_profiles WHERE id = ?`, id)
	return err
}

func joinIDList(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		if id > 0 {
			parts = append(parts, strconv.FormatInt(id, 10))
		}
	}
	return strings.Join(parts, ",")
}

func parseIDList(raw string) []int64 {
	out := []int64{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if id, err := strconv.ParseInt(part, 10, 64); err == nil && id > 0 {
			out = append(out, id)
		}
	}
	return out
}
