package store

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// ListProxies returns all proxies ordered by hostname.
func (s *Store) ListProxies() ([]model.Proxy, error) {
	rows, err := s.db.Query(`SELECT id, hostname, enabled, cert_id, profile_id, gate_mode, gate_secret,
		gate_totp_hint, fingerprint, bot_level, maintenance, waf_mode, created_at,
		protection_profile_id, access_profile_id, auth_provider_id,
		lb_policy, health_path, health_expect, health_interval, health_fail_after,
		max_inflight, max_inflight_per_client, upstream_timeout, retries,
		request_headers, response_headers, tls_min_version, max_body, body_skip, deny_paths, site_id FROM proxies WHERE (? = 0 OR site_id = ?) ORDER BY hostname`, s.site, s.site)
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
	var created, reqHeaders, respHeaders, bodySkip, denyPaths string
	err := row.Scan(&p.ID, &p.Hostname, &enabled, &certID, &profileID, &p.GateMode, &p.GateSecret,
		&p.GateTOTPHint, &p.Fingerprint, &p.BotLevel, &maint, &p.WAFMode, &created, &protectionID, &accessID, &providerID,
		&p.LBPolicy, &p.HealthPath, &p.HealthExpect, &p.HealthInterval, &p.HealthFailAfter,
		&p.MaxInflight, &p.MaxInflightPerClient, &p.UpstreamTimeout, &p.Retries, &reqHeaders, &respHeaders,
		&p.TLSMinVersion, &p.MaxBody, &bodySkip, &denyPaths, &p.SiteID)
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
	p.RequestHeaders = parseHeaderOps(reqHeaders)
	p.ResponseHeaders = parseHeaderOps(respHeaders)
	p.BodySkip = parseBodySkip(bodySkip)
	p.DenyPaths = parsePathList(denyPaths)
	return &p, nil
}

func bodySkipJSON(entries []model.BodySkip) string {
	if len(entries) == 0 {
		return "[]"
	}
	b, err := json.Marshal(entries)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func parseBodySkip(raw string) []model.BodySkip {
	var entries []model.BodySkip
	_ = json.Unmarshal([]byte(raw), &entries)
	return entries
}

func pathListJSON(paths []string) string {
	if len(paths) == 0 {
		return "[]"
	}
	b, err := json.Marshal(paths)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func parsePathList(raw string) []string {
	var paths []string
	_ = json.Unmarshal([]byte(raw), &paths)
	return paths
}

func headerOpsJSON(ops []model.HeaderOp) string {
	if len(ops) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ops)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func parseHeaderOps(raw string) []model.HeaderOp {
	var ops []model.HeaderOp
	_ = json.Unmarshal([]byte(raw), &ops)
	return ops
}

// GetProxy loads one proxy.
func (s *Store) GetProxy(id int64) (*model.Proxy, error) {
	return scanProxy(s.db.QueryRow(`SELECT id, hostname, enabled, cert_id, profile_id, gate_mode, gate_secret,
		gate_totp_hint, fingerprint, bot_level, maintenance, waf_mode, created_at,
		protection_profile_id, access_profile_id, auth_provider_id,
		lb_policy, health_path, health_expect, health_interval, health_fail_after,
		max_inflight, max_inflight_per_client, upstream_timeout, retries,
		request_headers, response_headers, tls_min_version, max_body, body_skip, deny_paths, site_id FROM proxies WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site))
}

// ProxyByHost loads a proxy by hostname.
func (s *Store) ProxyByHost(host string) (*model.Proxy, error) {
	return scanProxy(s.db.QueryRow(`SELECT id, hostname, enabled, cert_id, profile_id, gate_mode, gate_secret,
		gate_totp_hint, fingerprint, bot_level, maintenance, waf_mode, created_at,
		protection_profile_id, access_profile_id, auth_provider_id,
		lb_policy, health_path, health_expect, health_interval, health_fail_after,
		max_inflight, max_inflight_per_client, upstream_timeout, retries,
		request_headers, response_headers, tls_min_version, max_body, body_skip, deny_paths, site_id FROM proxies WHERE hostname = ? AND (? = 0 OR site_id = ?)`, host, s.site, s.site))
}

// CreateProxy inserts a proxy and returns its ID.
func (s *Store) CreateProxy(p *model.Proxy) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO proxies(hostname, enabled, cert_id, profile_id, gate_mode, gate_secret,
		gate_totp_hint, fingerprint, bot_level, maintenance, waf_mode, created_at,
		protection_profile_id, access_profile_id, auth_provider_id,
		lb_policy, health_path, health_expect, health_interval, health_fail_after,
		max_inflight, max_inflight_per_client, upstream_timeout, retries,
		request_headers, response_headers, tls_min_version, max_body, body_skip, deny_paths, site_id)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Hostname, b2i(p.Enabled), p.CertID, p.ProfileID, p.GateMode, p.GateSecret,
		p.GateTOTPHint, p.Fingerprint, defaultStr(p.BotLevel, "light"), b2i(p.Maintenance), p.WAFMode,
		stamp(time.Now()), p.ProtectionProfileID, p.AccessProfileID, p.AuthProviderID,
		defaultStr(p.LBPolicy, "weighted_rr"), defaultStr(p.HealthPath, "/"), defaultStr(p.HealthExpect, "200-399"),
		p.HealthInterval, p.HealthFailAfter, p.MaxInflight, p.MaxInflightPerClient,
		p.UpstreamTimeout, p.Retries, headerOpsJSON(p.RequestHeaders), headerOpsJSON(p.ResponseHeaders),
		p.TLSMinVersion, p.MaxBody, bodySkipJSON(p.BodySkip), pathListJSON(p.DenyPaths), s.site)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateProxy writes the mutable fields of a proxy.
func (s *Store) UpdateProxy(p *model.Proxy) error {
	_, err := s.db.Exec(`UPDATE proxies SET hostname = ?, enabled = ?, cert_id = ?, profile_id = ?,
		gate_mode = ?, gate_secret = ?, gate_totp_hint = ?, fingerprint = ?, bot_level = ?, maintenance = ?, waf_mode = ?,
		protection_profile_id = ?, access_profile_id = ?, auth_provider_id = ?,
		lb_policy = ?, health_path = ?, health_expect = ?, health_interval = ?, health_fail_after = ?,
		max_inflight = ?, max_inflight_per_client = ?, upstream_timeout = ?, retries = ?,
		request_headers = ?, response_headers = ?, tls_min_version = ?, max_body = ?, body_skip = ?, deny_paths = ?
		WHERE id = ? AND (? = 0 OR site_id = ?)`,
		p.Hostname, b2i(p.Enabled), p.CertID, p.ProfileID, p.GateMode, p.GateSecret,
		p.GateTOTPHint, p.Fingerprint, defaultStr(p.BotLevel, "light"), b2i(p.Maintenance), p.WAFMode,
		p.ProtectionProfileID, p.AccessProfileID, p.AuthProviderID,
		defaultStr(p.LBPolicy, "weighted_rr"), defaultStr(p.HealthPath, "/"), defaultStr(p.HealthExpect, "200-399"),
		p.HealthInterval, p.HealthFailAfter, p.MaxInflight, p.MaxInflightPerClient,
		p.UpstreamTimeout, p.Retries, headerOpsJSON(p.RequestHeaders), headerOpsJSON(p.ResponseHeaders),
		p.TLSMinVersion, p.MaxBody, bodySkipJSON(p.BodySkip), pathListJSON(p.DenyPaths), p.ID, s.site, s.site)
	return err
}

// DeleteProxy removes a proxy and its children.
func (s *Store) DeleteProxy(id int64) error {
	res, err := s.db.Exec(`DELETE FROM proxies WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListUpstreams returns the upstream pool of a proxy.
func (s *Store) ListUpstreams(proxyID int64) ([]model.Upstream, error) {
	if ok, err := s.ownsProxy(proxyID); err != nil {
		return nil, err
	} else if !ok {
		return nil, ErrNotFound
	}
	rows, err := s.db.Query(`SELECT id, proxy_id, url, weight, enabled, max_conns FROM upstreams WHERE proxy_id = ? ORDER BY id`, proxyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Upstream{}
	for rows.Next() {
		var u model.Upstream
		var enabled int
		if err := rows.Scan(&u.ID, &u.ProxyID, &u.URL, &u.Weight, &enabled, &u.MaxConns); err != nil {
			return nil, err
		}
		u.Enabled = i2b(enabled)
		out = append(out, u)
	}
	return out, rows.Err()
}

// ReplaceUpstreams replaces the whole upstream pool for a proxy.
func (s *Store) ReplaceUpstreams(proxyID int64, ups []model.Upstream) error {
	if ok, err := s.ownsProxy(proxyID); err != nil {
		return err
	} else if !ok {
		return ErrNotFound
	}
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
		if _, err := tx.Exec(`INSERT INTO upstreams(proxy_id, url, weight, enabled, max_conns) VALUES(?, ?, ?, ?, ?)`,
			proxyID, strings.TrimRight(u.URL, "/"), w, b2i(u.Enabled), u.MaxConns); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListRoutes returns the redirect/alias routes of a proxy.
func (s *Store) ListRoutes(proxyID int64) ([]model.Route, error) {
	if ok, err := s.ownsProxy(proxyID); err != nil {
		return nil, err
	} else if !ok {
		return nil, ErrNotFound
	}
	rows, err := s.db.Query(`SELECT id, proxy_id, kind, match, target, strip_prefix, priority,
		method, header, query, regex, upstream, timeout, status
		FROM routes WHERE proxy_id = ? ORDER BY priority DESC, id`, proxyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Route{}
	for rows.Next() {
		var r model.Route
		var strip, regex int
		if err := rows.Scan(&r.ID, &r.ProxyID, &r.Kind, &r.Match, &r.Target, &strip, &r.Priority,
			&r.Method, &r.Header, &r.Query, &regex, &r.Upstream, &r.Timeout, &r.Status); err != nil {
			return nil, err
		}
		r.StripPrefix = i2b(strip)
		r.Regex = i2b(regex)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ReplaceRoutes replaces all routes of a proxy.
func (s *Store) ReplaceRoutes(proxyID int64, routes []model.Route) error {
	if ok, err := s.ownsProxy(proxyID); err != nil {
		return err
	} else if !ok {
		return ErrNotFound
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM routes WHERE proxy_id = ?`, proxyID); err != nil {
		return err
	}
	for _, r := range routes {
		if _, err := tx.Exec(`INSERT INTO routes(proxy_id, kind, match, target, strip_prefix, priority,
			method, header, query, regex, upstream, timeout, status)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, proxyID, r.Kind, r.Match, r.Target,
			b2i(r.StripPrefix), r.Priority, r.Method, r.Header, r.Query, b2i(r.Regex),
			r.Upstream, r.Timeout, r.Status); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListProfiles returns all protection profiles.
func (s *Store) ListProfiles() ([]model.Profile, error) {
	rows, err := s.db.Query(`SELECT id, name, builtin, mode, paranoia, anomaly, allowed_methods, max_body, exceptions,
		responses, max_response, login_paths, login_rps, login_burst, admin_paths, admin_ips, bundle_modes
		FROM profiles WHERE (site_id = 0 OR site_id = ?) ORDER BY id`, s.site)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Profile{}
	for rows.Next() {
		var p model.Profile
		var builtin int
		var bundleModes string
		if err := rows.Scan(&p.ID, &p.Name, &builtin, &p.Mode, &p.Paranoia, &p.Anomaly,
			&p.AllowedMethods, &p.MaxBody, &p.Exceptions, &p.Responses, &p.MaxResponse, &p.LoginPaths,
			&p.LoginRPS, &p.LoginBurst, &p.AdminPaths, &p.AdminIPs, &bundleModes); err != nil {
			return nil, err
		}
		p.Builtin = i2b(builtin)
		p.BundleModes = decodeBundleModes(bundleModes)
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetProfile loads one profile.
func (s *Store) GetProfile(id int64) (*model.Profile, error) {
	var p model.Profile
	var builtin int
	var bundleModes string
	err := s.db.QueryRow(`SELECT id, name, builtin, mode, paranoia, anomaly, allowed_methods, max_body, exceptions,
		responses, max_response, login_paths, login_rps, login_burst, admin_paths, admin_ips, bundle_modes
		FROM profiles WHERE id = ? AND (site_id = 0 OR site_id = ?)`, id, s.site).
		Scan(&p.ID, &p.Name, &builtin, &p.Mode, &p.Paranoia, &p.Anomaly, &p.AllowedMethods, &p.MaxBody, &p.Exceptions,
			&p.Responses, &p.MaxResponse, &p.LoginPaths, &p.LoginRPS, &p.LoginBurst, &p.AdminPaths, &p.AdminIPs, &bundleModes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.Builtin = i2b(builtin)
	p.BundleModes = decodeBundleModes(bundleModes)
	return &p, nil
}

// UpdateProfile writes the tunable fields of a profile.
func (s *Store) UpdateProfile(p *model.Profile) error {
	_, err := s.db.Exec(`UPDATE profiles SET mode = ?, paranoia = ?, anomaly = ?, allowed_methods = ?,
		max_body = ?, exceptions = ?, responses = ?, max_response = ?, login_paths = ?, login_rps = ?, login_burst = ?,
		admin_paths = ?, admin_ips = ?, bundle_modes = ? WHERE id = ? AND site_id = ?`,
		p.Mode, p.Paranoia, p.Anomaly, p.AllowedMethods, p.MaxBody, p.Exceptions, p.Responses, p.MaxResponse,
		p.LoginPaths, p.LoginRPS, p.LoginBurst, p.AdminPaths, p.AdminIPs, encodeBundleModes(p.BundleModes), p.ID, s.site)
	return err
}

// CreateProfile inserts an operator-defined CRS profile.
func (s *Store) CreateProfile(p *model.Profile) error {
	var exists int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM profiles WHERE name = ? AND (site_id = 0 OR site_id = ?)`,
		p.Name, s.site).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return ErrDuplicate
	}
	if p.Responses == "" {
		p.Responses = "off"
	}
	res, err := s.db.Exec(`INSERT INTO profiles(name, builtin, mode, paranoia, anomaly, allowed_methods, max_body,
		exceptions, responses, max_response, login_paths, login_rps, login_burst, admin_paths, admin_ips, bundle_modes, site_id)
		VALUES(?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.Mode, p.Paranoia, p.Anomaly, p.AllowedMethods, p.MaxBody, p.Exceptions, p.Responses, p.MaxResponse,
		p.LoginPaths, p.LoginRPS, p.LoginBurst, p.AdminPaths, p.AdminIPs, encodeBundleModes(p.BundleModes), s.site)
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
	err := s.db.QueryRow(`SELECT COUNT(*) FROM proxies WHERE profile_id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site).Scan(&n)
	return n, err
}

// DeleteProfile removes an operator-defined profile.
func (s *Store) DeleteProfile(id int64) error {
	_, err := s.db.Exec(`DELETE FROM profiles WHERE id = ? AND builtin = 0 AND site_id = ?`, id, s.site)
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
	rows, err := s.db.Query(`SELECT id, domains, provider, status, issued_at, expires_at, is_wildcard, renew_mode, challenge, last_error, created_at, source
		FROM certificates WHERE (? = 0 OR site_id = ?) ORDER BY id`, s.site, s.site)
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
		if err := rows.Scan(&c.ID, &c.Domains, &c.Provider, &c.Status, &issued, &expires, &wildcard, &c.RenewMode, &c.Challenge, &c.LastError, &created, &c.Source); err != nil {
			return nil, err
		}
		c.IssuedAt = parseStampPtr(issued)
		c.ExpiresAt = parseStampPtr(expires)
		c.Wildcard = i2b(wildcard)
		c.RenewMode = defaultStr(c.RenewMode, model.CertRenewBeforeExpiry)
		c.Challenge = defaultStr(c.Challenge, model.CertChallengeDNS)
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
		is_wildcard, renew_mode, challenge, last_error, created_at, source FROM certificates WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site).
		Scan(&c.ID, &c.Domains, &c.Provider, &c.Status, &issued, &expires, &c.CertPEM, &c.KeyPEM,
			&wildcard, &c.RenewMode, &c.Challenge, &c.LastError, &created, &c.Source)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if c.KeyPEM, err = s.openSecret(c.KeyPEM); err != nil {
		return nil, err
	}
	c.IssuedAt = parseStampPtr(issued)
	c.ExpiresAt = parseStampPtr(expires)
	c.Wildcard = i2b(wildcard)
	c.RenewMode = defaultStr(c.RenewMode, model.CertRenewBeforeExpiry)
	c.Challenge = defaultStr(c.Challenge, model.CertChallengeDNS)
	c.CreatedAt = parseStamp(created)
	return &c, nil
}

// SealStoredCertKeys encrypts certificate private keys left in plaintext by an
// earlier release. It is idempotent and safe to run at every boot.
func (s *Store) SealStoredCertKeys() (int, error) {
	if s.box == nil {
		return 0, errors.New("store: no master key for certificate sealing")
	}
	rows, err := s.db.Query(`SELECT id, key_pem FROM certificates WHERE length(key_pem) > 0`)
	if err != nil {
		return 0, err
	}
	type row struct {
		id  int64
		key []byte
	}
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.key); err != nil {
			rows.Close()
			return 0, err
		}
		if !bytes.HasPrefix(r.key, []byte(sealedPrefix)) {
			pending = append(pending, r)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, r := range pending {
		sealed, err := s.sealSecret(r.key)
		if err != nil {
			return n, err
		}
		if _, err := s.db.Exec(`UPDATE certificates SET key_pem = ? WHERE id = ?`, sealed, r.id); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// SaveCert inserts or updates a certificate. A zero ID inserts.
func (s *Store) SaveCert(c *model.Cert) (int64, error) {
	key, err := s.sealSecret(c.KeyPEM)
	if err != nil {
		return 0, err
	}
	if c.ID == 0 {
		res, err := s.db.Exec(`INSERT INTO certificates(domains, provider, status, issued_at, expires_at,
			cert_pem, key_pem, is_wildcard, renew_mode, challenge, last_error, created_at, source, site_id)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.Domains, c.Provider, c.Status, nullTime(c.IssuedAt), nullTime(c.ExpiresAt),
			c.CertPEM, key, b2i(c.Wildcard), defaultStr(c.RenewMode, model.CertRenewBeforeExpiry),
			defaultStr(c.Challenge, model.CertChallengeDNS), c.LastError, stamp(time.Now()),
			defaultStr(c.Source, model.CertSourceACME), s.site)
		if err != nil {
			return 0, err
		}
		return res.LastInsertId()
	}
	_, err = s.db.Exec(`UPDATE certificates SET domains = ?, provider = ?, status = ?, issued_at = ?,
		expires_at = ?, cert_pem = ?, key_pem = ?, is_wildcard = ?, renew_mode = ?, challenge = ?, last_error = ?, source = ? WHERE id = ? AND (? = 0 OR site_id = ?)`,
		c.Domains, c.Provider, c.Status, nullTime(c.IssuedAt), nullTime(c.ExpiresAt),
		c.CertPEM, key, b2i(c.Wildcard), defaultStr(c.RenewMode, model.CertRenewBeforeExpiry),
		defaultStr(c.Challenge, model.CertChallengeDNS), c.LastError, defaultStr(c.Source, model.CertSourceACME), c.ID, s.site, s.site)
	return c.ID, err
}

// SetCertRenewMode updates one certificate's renewal policy without touching
// its key material.
func (s *Store) SetCertRenewMode(id int64, mode string) error {
	res, err := s.db.Exec(`UPDATE certificates SET renew_mode = ? WHERE id = ? AND (? = 0 OR site_id = ?)`, mode, id, s.site, s.site)
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
	_, err := s.db.Exec(`DELETE FROM certificates WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site)
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

// ownsProxy reports whether a proxy belongs to this store's site, so a scoped
// handle cannot read or replace another site's upstreams and routes.
func (s *Store) ownsProxy(id int64) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM proxies WHERE id = ? AND (? = 0 OR site_id = ?)`,
		id, s.site, s.site).Scan(&n)
	return n > 0, err
}
