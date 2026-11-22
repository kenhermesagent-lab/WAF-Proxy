package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// ListProxies returns all proxies ordered by hostname.
func (s *Store) ListProxies() ([]model.Proxy, error) {
	rows, err := s.db.Query(`SELECT id, hostname, enabled, cert_id, profile_id, gate_mode, gate_secret,
		gate_totp_hint, fingerprint, bot_level, maintenance, waf_mode, created_at,
		protection_profile_id, access_profile_id, auth_provider_id FROM proxies ORDER BY hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Proxy{}
	for rows.Next() {
		p, err := scanProxy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

func scanProxy(row interface{ Scan(...any) error }) (*model.Proxy, error) {
	var p model.Proxy
	var certID, profileID, protectionID, accessID, providerID sql.NullInt64
	var enabled, maint int
	var created string
	err := row.Scan(&p.ID, &p.Hostname, &enabled, &certID, &profileID, &p.GateMode, &p.GateSecret,
		&p.GateTOTPHint, &p.Fingerprint, &p.BotLevel, &maint, &p.WAFMode, &created, &protectionID, &accessID, &providerID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.Enabled = i2b(enabled)
	p.Maintenance = i2b(maint)
	if certID.Valid {
		p.CertID = &certID.Int64
	}
	if profileID.Valid {
		p.ProfileID = &profileID.Int64
	}
	if protectionID.Valid {
		p.ProtectionProfileID = &protectionID.Int64
	}
	if accessID.Valid {
		p.AccessProfileID = &accessID.Int64
	}
	if providerID.Valid {
		p.AuthProviderID = &providerID.Int64
	}
	p.CreatedAt = parseStamp(created)
	return &p, nil
}

// GetProxy loads one proxy.
func (s *Store) GetProxy(id int64) (*model.Proxy, error) {
	return scanProxy(s.db.QueryRow(`SELECT id, hostname, enabled, cert_id, profile_id, gate_mode, gate_secret,
		gate_totp_hint, fingerprint, bot_level, maintenance, waf_mode, created_at,
		protection_profile_id, access_profile_id, auth_provider_id FROM proxies WHERE id = ?`, id))
}

// ProxyByHost loads a proxy by hostname.
func (s *Store) ProxyByHost(host string) (*model.Proxy, error) {
	return scanProxy(s.db.QueryRow(`SELECT id, hostname, enabled, cert_id, profile_id, gate_mode, gate_secret,
		gate_totp_hint, fingerprint, bot_level, maintenance, waf_mode, created_at,
		protection_profile_id, access_profile_id, auth_provider_id FROM proxies WHERE hostname = ?`, host))
}

// CreateProxy inserts a proxy and returns its ID.
func (s *Store) CreateProxy(p *model.Proxy) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO proxies(hostname, enabled, cert_id, profile_id, gate_mode, gate_secret,
		gate_totp_hint, fingerprint, bot_level, maintenance, waf_mode, created_at,
		protection_profile_id, access_profile_id, auth_provider_id)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Hostname, b2i(p.Enabled), p.CertID, p.ProfileID, p.GateMode, p.GateSecret,
		p.GateTOTPHint, p.Fingerprint, defaultStr(p.BotLevel, "light"), b2i(p.Maintenance), p.WAFMode,
		stamp(time.Now()), p.ProtectionProfileID, p.AccessProfileID, p.AuthProviderID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateProxy writes the mutable fields of a proxy.
func (s *Store) UpdateProxy(p *model.Proxy) error {
	_, err := s.db.Exec(`UPDATE proxies SET hostname = ?, enabled = ?, cert_id = ?, profile_id = ?,
		gate_mode = ?, gate_secret = ?, gate_totp_hint = ?, fingerprint = ?, bot_level = ?, maintenance = ?, waf_mode = ?,
		protection_profile_id = ?, access_profile_id = ?, auth_provider_id = ?
		WHERE id = ?`,
		p.Hostname, b2i(p.Enabled), p.CertID, p.ProfileID, p.GateMode, p.GateSecret,
		p.GateTOTPHint, p.Fingerprint, defaultStr(p.BotLevel, "light"), b2i(p.Maintenance), p.WAFMode,
		p.ProtectionProfileID, p.AccessProfileID, p.AuthProviderID, p.ID)
	return err
}

// DeleteProxy removes a proxy and its children.
func (s *Store) DeleteProxy(id int64) error {
	_, err := s.db.Exec(`DELETE FROM proxies WHERE id = ?`, id)
	return err
}

// ListUpstreams returns the upstream pool of a proxy.
func (s *Store) ListUpstreams(proxyID int64) ([]model.Upstream, error) {
	rows, err := s.db.Query(`SELECT id, proxy_id, url, weight, enabled FROM upstreams WHERE proxy_id = ? ORDER BY id`, proxyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Upstream{}
	for rows.Next() {
		var u model.Upstream
		var enabled int
		if err := rows.Scan(&u.ID, &u.ProxyID, &u.URL, &u.Weight, &enabled); err != nil {
			return nil, err
		}
		u.Enabled = i2b(enabled)
		out = append(out, u)
	}
	return out, rows.Err()
}

// ReplaceUpstreams replaces the whole upstream pool for a proxy.
func (s *Store) ReplaceUpstreams(proxyID int64, ups []model.Upstream) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM upstreams WHERE proxy_id = ?`, proxyID); err != nil {
		return err
	}
	for _, u := range ups {
		w := u.Weight
		if w <= 0 {
			w = 1
		}
		if _, err := tx.Exec(`INSERT INTO upstreams(proxy_id, url, weight, enabled) VALUES(?, ?, ?, ?)`,
			proxyID, strings.TrimRight(u.URL, "/"), w, b2i(u.Enabled)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListRoutes returns the redirect/alias routes of a proxy.
func (s *Store) ListRoutes(proxyID int64) ([]model.Route, error) {
	rows, err := s.db.Query(`SELECT id, proxy_id, kind, match, target, strip_prefix, priority
		FROM routes WHERE proxy_id = ? ORDER BY priority DESC, id`, proxyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Route{}
	for rows.Next() {
		var r model.Route
		var strip int
		if err := rows.Scan(&r.ID, &r.ProxyID, &r.Kind, &r.Match, &r.Target, &strip, &r.Priority); err != nil {
			return nil, err
		}
		r.StripPrefix = i2b(strip)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ReplaceRoutes replaces all routes of a proxy.
func (s *Store) ReplaceRoutes(proxyID int64, routes []model.Route) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM routes WHERE proxy_id = ?`, proxyID); err != nil {
		return err
	}
	for _, r := range routes {
		if _, err := tx.Exec(`INSERT INTO routes(proxy_id, kind, match, target, strip_prefix, priority)
			VALUES(?, ?, ?, ?, ?, ?)`, proxyID, r.Kind, r.Match, r.Target, b2i(r.StripPrefix), r.Priority); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListProfiles returns all protection profiles.
func (s *Store) ListProfiles() ([]model.Profile, error) {
	rows, err := s.db.Query(`SELECT id, name, builtin, mode, paranoia, anomaly, allowed_methods, max_body, exceptions,
		max_response, login_paths, login_rps, login_burst, admin_paths, admin_ips
		FROM profiles ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Profile{}
	for rows.Next() {
		var p model.Profile
		var builtin int
		if err := rows.Scan(&p.ID, &p.Name, &builtin, &p.Mode, &p.Paranoia, &p.Anomaly,
			&p.AllowedMethods, &p.MaxBody, &p.Exceptions, &p.MaxResponse, &p.LoginPaths,
			&p.LoginRPS, &p.LoginBurst, &p.AdminPaths, &p.AdminIPs); err != nil {
			return nil, err
		}
		p.Builtin = i2b(builtin)
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetProfile loads one profile.
func (s *Store) GetProfile(id int64) (*model.Profile, error) {
	var p model.Profile
	var builtin int
	err := s.db.QueryRow(`SELECT id, name, builtin, mode, paranoia, anomaly, allowed_methods, max_body, exceptions,
		max_response, login_paths, login_rps, login_burst, admin_paths, admin_ips
		FROM profiles WHERE id = ?`, id).
		Scan(&p.ID, &p.Name, &builtin, &p.Mode, &p.Paranoia, &p.Anomaly, &p.AllowedMethods, &p.MaxBody, &p.Exceptions,
			&p.MaxResponse, &p.LoginPaths, &p.LoginRPS, &p.LoginBurst, &p.AdminPaths, &p.AdminIPs)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.Builtin = i2b(builtin)
	return &p, nil
}

// UpdateProfile writes the tunable fields of a profile.
func (s *Store) UpdateProfile(p *model.Profile) error {
	_, err := s.db.Exec(`UPDATE profiles SET mode = ?, paranoia = ?, anomaly = ?, allowed_methods = ?,
		max_body = ?, exceptions = ?, max_response = ?, login_paths = ?, login_rps = ?, login_burst = ?,
		admin_paths = ?, admin_ips = ? WHERE id = ?`,
		p.Mode, p.Paranoia, p.Anomaly, p.AllowedMethods, p.MaxBody, p.Exceptions, p.MaxResponse,
		p.LoginPaths, p.LoginRPS, p.LoginBurst, p.AdminPaths, p.AdminIPs, p.ID)
	return err
}

// CreateProfile inserts an operator-defined CRS profile.
func (s *Store) CreateProfile(p *model.Profile) error {
	var exists int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM profiles WHERE name = ?`, p.Name).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return ErrDuplicate
	}
	res, err := s.db.Exec(`INSERT INTO profiles(name, builtin, mode, paranoia, anomaly, allowed_methods, max_body,
		exceptions, max_response, login_paths, login_rps, login_burst, admin_paths, admin_ips)
		VALUES(?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.Mode, p.Paranoia, p.Anomaly, p.AllowedMethods, p.MaxBody, p.Exceptions, p.MaxResponse,
		p.LoginPaths, p.LoginRPS, p.LoginBurst, p.AdminPaths, p.AdminIPs)
	if err != nil {
		return err
	}
	p.ID, err = res.LastInsertId()
	return err
}

// ProfileInUse counts the proxies still selecting a profile. The column is
// declared ON DELETE SET NULL, so deleting without this check would silently
// move those sites to the default profile.
func (s *Store) ProfileInUse(id int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM proxies WHERE profile_id = ?`, id).Scan(&n)
	return n, err
}

// DeleteProfile removes an operator-defined profile.
func (s *Store) DeleteProfile(id int64) error {
	_, err := s.db.Exec(`DELETE FROM profiles WHERE id = ? AND builtin = 0`, id)
	return err
}

func defaultStr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func (s *Store) seedProfiles() error {
	builtins := []model.Profile{
		{Name: "Generic Web", Mode: "block", Paranoia: 1, Anomaly: 5, AllowedMethods: "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS", MaxBody: 131072},
		{Name: "WordPress", Mode: "block", Paranoia: 2, Anomaly: 5, AllowedMethods: "GET,HEAD,POST", MaxBody: 524288},
		{Name: "API-only", Mode: "block", Paranoia: 2, Anomaly: 3, AllowedMethods: "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS", MaxBody: 1048576},
		{Name: "Static / CDN", Mode: "block", Paranoia: 1, Anomaly: 3, AllowedMethods: "GET,HEAD,OPTIONS", MaxBody: 8192},
		{Name: "Admin panel (strict)", Mode: "block", Paranoia: 3, Anomaly: 3, AllowedMethods: "GET,HEAD,POST", MaxBody: 65536},
	}
	for _, p := range builtins {
		_, err := s.db.Exec(`INSERT INTO profiles(name, builtin, mode, paranoia, anomaly, allowed_methods, max_body)
			VALUES(?, 1, ?, ?, ?, ?, ?)
			ON CONFLICT(name) DO NOTHING`, p.Name, p.Mode, p.Paranoia, p.Anomaly, p.AllowedMethods, p.MaxBody)
		if err != nil {
			return err
		}
	}
	return nil
}

// ListCerts returns all certificates.
func (s *Store) ListCerts() ([]model.Cert, error) {
	rows, err := s.db.Query(`SELECT id, domains, provider, status, issued_at, expires_at, is_wildcard, renew_mode, last_error, created_at
		FROM certificates ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Cert{}
	for rows.Next() {
		var c model.Cert
		var issued, expires sql.NullString
		var wildcard int
		var created string
		if err := rows.Scan(&c.ID, &c.Domains, &c.Provider, &c.Status, &issued, &expires, &wildcard, &c.RenewMode, &c.LastError, &created); err != nil {
			return nil, err
		}
		c.IssuedAt = parseStampPtr(issued)
		c.ExpiresAt = parseStampPtr(expires)
		c.Wildcard = i2b(wildcard)
		c.RenewMode = defaultStr(c.RenewMode, model.CertRenewBeforeExpiry)
		c.CreatedAt = parseStamp(created)
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetCert loads one certificate including its key material.
func (s *Store) GetCert(id int64) (*model.Cert, error) {
	var c model.Cert
	var issued, expires sql.NullString
	var wildcard int
	var created string
	err := s.db.QueryRow(`SELECT id, domains, provider, status, issued_at, expires_at, cert_pem, key_pem,
		is_wildcard, renew_mode, last_error, created_at FROM certificates WHERE id = ?`, id).
		Scan(&c.ID, &c.Domains, &c.Provider, &c.Status, &issued, &expires, &c.CertPEM, &c.KeyPEM,
			&wildcard, &c.RenewMode, &c.LastError, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.IssuedAt = parseStampPtr(issued)
	c.ExpiresAt = parseStampPtr(expires)
	c.Wildcard = i2b(wildcard)
	c.RenewMode = defaultStr(c.RenewMode, model.CertRenewBeforeExpiry)
	c.CreatedAt = parseStamp(created)
	return &c, nil
}

// SaveCert inserts or updates a certificate. A zero ID inserts.
func (s *Store) SaveCert(c *model.Cert) (int64, error) {
	if c.ID == 0 {
		res, err := s.db.Exec(`INSERT INTO certificates(domains, provider, status, issued_at, expires_at,
			cert_pem, key_pem, is_wildcard, renew_mode, last_error, created_at)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.Domains, c.Provider, c.Status, nullTime(c.IssuedAt), nullTime(c.ExpiresAt),
			c.CertPEM, c.KeyPEM, b2i(c.Wildcard), defaultStr(c.RenewMode, model.CertRenewBeforeExpiry),
			c.LastError, stamp(time.Now()))
		if err != nil {
			return 0, err
		}
		return res.LastInsertId()
	}
	_, err := s.db.Exec(`UPDATE certificates SET domains = ?, provider = ?, status = ?, issued_at = ?,
		expires_at = ?, cert_pem = ?, key_pem = ?, is_wildcard = ?, renew_mode = ?, last_error = ? WHERE id = ?`,
		c.Domains, c.Provider, c.Status, nullTime(c.IssuedAt), nullTime(c.ExpiresAt),
		c.CertPEM, c.KeyPEM, b2i(c.Wildcard), defaultStr(c.RenewMode, model.CertRenewBeforeExpiry),
		c.LastError, c.ID)
	return c.ID, err
}

// SetCertRenewMode updates one certificate's renewal policy without touching
// its key material.
func (s *Store) SetCertRenewMode(id int64, mode string) error {
	res, err := s.db.Exec(`UPDATE certificates SET renew_mode = ? WHERE id = ?`, mode, id)
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

// DeleteCert removes a certificate.
func (s *Store) DeleteCert(id int64) error {
	_, err := s.db.Exec(`DELETE FROM certificates WHERE id = ?`, id)
	return err
}

// CertsForSNI returns certificates that may answer for the given hostname.
func (s *Store) CertsForSNI(host string) ([]model.Cert, error) {
	certs, err := s.ListCerts()
	if err != nil {
		return nil, err
	}
	out := []model.Cert{}
	for _, c := range certs {
		if c.Status != "issued" && c.Status != "renewing" {
			continue
		}
		for _, d := range strings.Split(c.Domains, ",") {
			d = strings.TrimSpace(d)
			if d == host || (strings.HasPrefix(d, "*.") && strings.HasSuffix(host, d[1:]) && strings.Count(host, ".") == strings.Count(d, ".")) {
				out = append(out, c)
				break
			}
		}
	}
	return out, nil
}
