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
	rows, err := s.db.Query(`SELECT `+protectionProfileColumns+`
		FROM protection_profiles WHERE (site_id = 0 OR site_id = ?) ORDER BY id`, s.site)
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
	row := s.db.QueryRow(`SELECT `+protectionProfileColumns+` FROM protection_profiles
		WHERE id = ? AND (site_id = 0 OR site_id = ?)`, id, s.site)
	return scanProtectionProfile(row)
}

// CreateProtectionProfile inserts an operator-defined profile.
func (s *Store) CreateProtectionProfile(p *model.ProtectionProfile) error {
	var exists int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM protection_profiles WHERE name = ? AND site_id = ?`,
		p.Name, s.site).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return ErrDuplicate
	}
	res, err := s.db.Exec(`INSERT INTO protection_profiles(name, builtin, force_https, hsts, hsts_subdomains,
		frame_options, nosniff, referrer_policy, csp, permissions_policy, hide_server, site_id)
		VALUES(?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, b2i(p.ForceHTTPS), b2i(p.HSTS), b2i(p.HSTSSubdomains), p.FrameOptions,
		b2i(p.NoSniff), p.ReferrerPolicy, p.CSP, p.PermissionsPolicy, b2i(p.HideServer), s.site)
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
		WHERE id = ? AND site_id = ?`,
		b2i(p.ForceHTTPS), b2i(p.HSTS), b2i(p.HSTSSubdomains), p.FrameOptions, b2i(p.NoSniff),
		p.ReferrerPolicy, p.CSP, p.PermissionsPolicy, b2i(p.HideServer), p.ID, s.site)
	return err
}

// ProtectionProfileInUse counts the proxies selecting a profile.
func (s *Store) ProtectionProfileInUse(id int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM proxies WHERE protection_profile_id = ? AND (? = 0 OR site_id = ?)`,
		id, s.site, s.site).Scan(&n)
	return n, err
}

// DeleteProtectionProfile removes an operator-defined profile.
func (s *Store) DeleteProtectionProfile(id int64) error {
	_, err := s.db.Exec(`DELETE FROM protection_profiles WHERE id = ? AND builtin = 0 AND site_id = ?`, id, s.site)
	return err
}

func (s *Store) seedProtectionProfiles() error {
	_, err := s.db.Exec(`INSERT INTO protection_profiles(name, builtin, force_https, hsts, hsts_subdomains,
		frame_options, nosniff, referrer_policy, hide_server)
		VALUES('Recommended hardening', 1, 1, 1, 1, 'sameorigin', 1, 'strict-origin-when-cross-origin', 1)
		ON CONFLICT(name) DO NOTHING`)
	return err
}

const accessProfileColumns = `id, name, policy_ids, rule_roles, list_ids, waf_profile_id, protection_profile_id, waf_skip_list_ids`

// The roles column is parallel to the id list, so a profile can mark the same
// list allow in one profile and deny in another.
func scanAccessProfile(row interface{ Scan(...any) error }) (*model.AccessProfile, error) {
	var a model.AccessProfile
	var ids, roles, listIDs, skipIDs string
	var waf, prot sql.NullInt64
	err := row.Scan(&a.ID, &a.Name, &ids, &roles, &listIDs, &waf, &prot, &skipIDs)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	roleList := strings.Split(roles, ",")
	// Always a list: the console renders it and JSON null would break the page.
	a.Rules = []model.AccessRule{}
	for i, id := range parseIDList(ids) {
		role := model.AccessRoleInherit
		if i < len(roleList) {
			switch strings.TrimSpace(roleList[i]) {
			case model.AccessRoleAllow, model.AccessRoleDeny:
				role = strings.TrimSpace(roleList[i])
			}
		}
		a.Rules = append(a.Rules, model.AccessRule{PolicyID: id, Role: role})
	}
	a.ListIDs = parseIDList(listIDs)
	a.WAFSkipListIDs = parseIDList(skipIDs)
	if waf.Valid {
		v := waf.Int64
		a.WAFProfileID = &v
	}
	if prot.Valid {
		v := prot.Int64
		a.ProtectionProfileID = &v
	}
	return &a, nil
}

func accessProfileValues(a *model.AccessProfile) (string, string) {
	ids := make([]string, 0, len(a.Rules))
	roles := make([]string, 0, len(a.Rules))
	for _, r := range a.Rules {
		if r.PolicyID <= 0 {
			continue
		}
		role := r.Role
		if role != model.AccessRoleAllow && role != model.AccessRoleDeny {
			role = model.AccessRoleInherit
		}
		ids = append(ids, strconv.FormatInt(r.PolicyID, 10))
		roles = append(roles, role)
	}
	return strings.Join(ids, ","), strings.Join(roles, ",")
}

// accessListValues serialises the attached list ids, deduplicated so a double
// click in the console cannot add the same list twice.
func accessListValues(a *model.AccessProfile) string {
	seen := map[int64]bool{}
	ids := make([]string, 0, len(a.ListIDs))
	for _, id := range a.ListIDs {
		if id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, strconv.FormatInt(id, 10))
	}
	return strings.Join(ids, ",")
}

// ListAccessProfiles returns the named access profiles.
func (s *Store) ListAccessProfiles() ([]model.AccessProfile, error) {
	rows, err := s.db.Query(`SELECT `+accessProfileColumns+`
		FROM access_profiles WHERE (? = 0 OR site_id = ?) ORDER BY id`, s.site, s.site)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AccessProfile{}
	for rows.Next() {
		a, err := scanAccessProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// GetAccessProfile loads one profile.
func (s *Store) GetAccessProfile(id int64) (*model.AccessProfile, error) {
	return scanAccessProfile(s.db.QueryRow(`SELECT `+accessProfileColumns+`
		FROM access_profiles WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site))
}

// CreateAccessProfile inserts a profile.
func (s *Store) CreateAccessProfile(a *model.AccessProfile) error {
	var exists int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM access_profiles WHERE name = ? AND site_id = ?`,
		a.Name, s.site).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return ErrDuplicate
	}
	ids, roles := accessProfileValues(a)
	res, err := s.db.Exec(`INSERT INTO access_profiles(name, policy_ids, rule_roles, list_ids, waf_profile_id, protection_profile_id, waf_skip_list_ids, site_id)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, a.Name, ids, roles, accessListValues(a), a.WAFProfileID, a.ProtectionProfileID,
		accessListValues(&model.AccessProfile{ListIDs: a.WAFSkipListIDs}), s.site)
	if err != nil {
		return err
	}
	a.ID, err = res.LastInsertId()
	return err
}

// UpdateAccessProfile replaces a profile's lists, roles and protection choice.
func (s *Store) UpdateAccessProfile(a *model.AccessProfile) error {
	ids, roles := accessProfileValues(a)
	_, err := s.db.Exec(`UPDATE access_profiles SET policy_ids = ?, rule_roles = ?, list_ids = ?, waf_profile_id = ?,
		protection_profile_id = ?, waf_skip_list_ids = ? WHERE id = ? AND (? = 0 OR site_id = ?)`,
		ids, roles, accessListValues(a), a.WAFProfileID, a.ProtectionProfileID,
		accessListValues(&model.AccessProfile{ListIDs: a.WAFSkipListIDs}), a.ID, s.site, s.site)
	return err
}

// AccessProfileInUse counts the proxies selecting a bundle.
func (s *Store) AccessProfileInUse(id int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM proxies WHERE access_profile_id = ? AND (? = 0 OR site_id = ?)`,
		id, s.site, s.site).Scan(&n)
	return n, err
}

// DeleteAccessProfile removes a bundle. The policies themselves are untouched.
func (s *Store) DeleteAccessProfile(id int64) error {
	_, err := s.db.Exec(`DELETE FROM access_profiles WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site)
	return err
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
