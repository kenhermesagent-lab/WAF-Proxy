package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// DefaultSiteSlug owns every row written before sites existed.
const DefaultSiteSlug = "default"

// scopedTables carry a site_id. Every row belongs to exactly one site; the
// builtin profiles, protection profiles and feeds are seeded with 0, which
// means "shared by every site" and is read as an overlay, never edited per
// site.
var scopedTables = []string{
	"users", "sessions", "profiles", "certificates", "dns_credentials",
	"auth_providers", "proxies", "protection_profiles", "access_profiles",
	"access_lists", "policies", "bans", "feeds", "alerts", "audit",
	"gate_users", "agent_deliveries", "agent_links", "anomaly_events",
	"gate_failures", "gate_sessions", "username_bans", "mcp_tokens", "log_views",
	"trusted_devices", "password_resets",
}

// hostSettingKeys are process-wide: one listener, one address, one update
// schedule. A site_settings row for one of these is ignored, so a tenant
// cannot move the host's bind address by editing its own console.
var hostSettingKeys = map[string]bool{
	"wan_ip": true, "wan_port": true, "wan_iface": true,
	"lan_ip": true, "lan_iface": true, "gui_port": true,
	"admin_allow_cidrs": true, "home_lat": true, "home_lon": true,
	"auto_update_enabled": true, "auto_update_time": true,
	"geoip_auto_update": true,
	"crowdsec_enabled":  true, "crowdsec_url": true, "crowdsec_key": true,
	"tailscale_admin_enabled": true, "tailscale_dns_enabled": true,
	"tailscale_proxy_enabled": true,
}

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,31}$`)

// consoleHostPattern matches a bare DNS name, so a pasted URL or a path is
// refused with a message instead of becoming a site nobody can reach.
var consoleHostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

func checkConsoleHost(raw string) error {
	h := strings.TrimSpace(raw)
	if h == "" {
		return nil
	}
	if strings.Contains(h, "://") || strings.ContainsAny(h, "/ \t?#") {
		return fmt.Errorf("console host %q is not a hostname (enter a name such as console.example.com)", raw)
	}
	n := NormalizeHost(h)
	if !consoleHostPattern.MatchString(n) || strings.Contains(n, "..") {
		return fmt.Errorf("console host %q is not a hostname (enter a name such as console.example.com)", raw)
	}
	return nil
}

// NormalizeHost lowercases a host and drops any port and trailing dot, so a
// request's Host header and a configured console host compare equal.
func NormalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if withoutPort, _, err := net.SplitHostPort(h); err == nil {
		h = withoutPort
	}
	return strings.TrimSuffix(h, ".")
}

// CreateSite inserts a site and returns it. A slug or console host already in
// use returns ErrDuplicate.
func (s *Store) CreateSite(slug, name, consoleHost string) (*model.Site, error) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	name = strings.TrimSpace(name)
	host := NormalizeHost(consoleHost)
	if !slugPattern.MatchString(slug) {
		return nil, fmt.Errorf("slug must be 2-32 characters of a-z, 0-9 and -")
	}
	if name == "" {
		name = slug
	}
	if err := checkConsoleHost(consoleHost); err != nil {
		return nil, err
	}
	res, err := s.db.Exec(`INSERT INTO sites(slug, name, console_host, enabled, created_at)
		VALUES(?, ?, ?, 1, ?)`, slug, name, host, stamp(time.Now()))
	if err != nil {
		if isUniqueErr(err) {
			return nil, ErrDuplicate
		}
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return s.SiteByID(id)
}

// ListSites returns every site ordered by slug.
func (s *Store) ListSites() ([]model.Site, error) {
	rows, err := s.db.Query(`SELECT id, slug, name, console_host, enabled, created_at FROM sites ORDER BY slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Site{}
	for rows.Next() {
		site, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *site)
	}
	return out, rows.Err()
}

// SiteByID loads one site.
func (s *Store) SiteByID(id int64) (*model.Site, error) {
	return scanSite(s.db.QueryRow(`SELECT id, slug, name, console_host, enabled, created_at
		FROM sites WHERE id = ?`, id))
}

// SiteBySlug loads one site by its stable slug.
func (s *Store) SiteBySlug(slug string) (*model.Site, error) {
	return scanSite(s.db.QueryRow(`SELECT id, slug, name, console_host, enabled, created_at
		FROM sites WHERE slug = ?`, strings.ToLower(strings.TrimSpace(slug))))
}

// SiteByConsoleHost resolves the console a request's Host header belongs to.
func (s *Store) SiteByConsoleHost(host string) (*model.Site, error) {
	return scanSite(s.db.QueryRow(`SELECT id, slug, name, console_host, enabled, created_at
		FROM sites WHERE console_host = ? AND enabled = 1`, NormalizeHost(host)))
}

func scanSite(row interface{ Scan(...any) error }) (*model.Site, error) {
	var site model.Site
	var enabled int
	var created string
	err := row.Scan(&site.ID, &site.Slug, &site.Name, &site.ConsoleHost, &enabled, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	site.Enabled = i2b(enabled)
	site.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return &site, nil
}

// UpdateSite changes a site's name, console host or enabled flag.
func (s *Store) UpdateSite(id int64, name, consoleHost string, enabled bool) (*model.Site, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("a site needs a name")
	}
	if err := checkConsoleHost(consoleHost); err != nil {
		return nil, err
	}
	_, err := s.db.Exec(`UPDATE sites SET name = ?, console_host = ?, enabled = ? WHERE id = ?`,
		name, NormalizeHost(consoleHost), b2i(enabled), id)
	if err != nil {
		if isUniqueErr(err) {
			return nil, ErrDuplicate
		}
		return nil, err
	}
	return s.SiteByID(id)
}

// DeleteSite removes a site and every row it owns. The default site is the
// one that adopted the install's history, so it is never removed.
func (s *Store) DeleteSite(id int64) error {
	site, err := s.SiteByID(id)
	if err != nil {
		return err
	}
	if site.Slug == DefaultSiteSlug {
		return fmt.Errorf("the default site cannot be removed")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, table := range scopedTables {
		if _, err := tx.Exec(`DELETE FROM `+table+` WHERE site_id = ?`, id); err != nil {
			return fmt.Errorf("delete %s rows: %w", table, err)
		}
	}
	for _, stmt := range []string{
		`DELETE FROM site_settings WHERE site_id = ?`,
		`DELETE FROM sites WHERE id = ?`,
	} {
		if _, err := tx.Exec(stmt, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SettingsFor returns the settings a site sees: the host's table with the
// site's own overrides on top. Host-wide keys always come from the host.
func (s *Store) SettingsFor(siteID int64) (map[string]string, error) {
	out := map[string]string{}
	host, err := s.db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	for host.Next() {
		var k, v string
		if err := host.Scan(&k, &v); err != nil {
			host.Close()
			return nil, err
		}
		out[k] = v
	}
	host.Close()
	rows, err := s.db.Query(`SELECT key, value FROM site_settings WHERE site_id = ?`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		if !hostSettingKeys[k] {
			out[k] = v
		}
	}
	return out, rows.Err()
}

// SetSettingsFor writes a site's overrides. Host-wide keys are dropped rather
// than refused so a console that posts its whole settings form still saves the
// keys it is allowed to change.
func (s *Store) SetSettingsFor(siteID int64, kv map[string]string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for k, v := range kv {
		if hostSettingKeys[k] {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO site_settings(site_id, key, value) VALUES(?, ?, ?)
			ON CONFLICT(site_id, key) DO UPDATE SET value = excluded.value`, siteID, k, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// adoptMerges resolves the rows a binary rolled back to before sites leaves
// without a site. Such a row can repeat one the default site already has under
// a key that includes site_id, which the adoption update refuses, so each table
// keeps one row per key first: the stronger ban, the newer saved view. Every
// table whose uniqueness includes site_id needs an entry here;
// TestAdoptionMergesEverySiteUniqueKey fails without one.
var adoptMerges = map[string]string{
	"bans": `DELETE FROM bans WHERE site_id IN (0, ?) AND id NOT IN (
		SELECT id FROM (
			SELECT id, ROW_NUMBER() OVER (
				PARTITION BY cidr
				ORDER BY permanent DESC, COALESCE(expires_at, '9999') DESC, created_at DESC, id DESC
			) AS rn FROM bans WHERE site_id IN (0, ?)
		) WHERE rn = 1)`,
	"log_views": `DELETE FROM log_views WHERE site_id IN (0, ?) AND (name, site_id) NOT IN (
		SELECT name, site_id FROM (
			SELECT name, site_id, ROW_NUMBER() OVER (
				PARTITION BY name ORDER BY updated_at DESC, site_id DESC
			) AS rn FROM log_views WHERE site_id IN (0, ?)
		) WHERE rn = 1)`,
}

// migrateSites creates the site that adopts the install's existing rows and
// assigns every unowned row to it. It runs after the builtin seeds, so a fresh
// database and an upgraded one end up with the same single site.
func (s *Store) migrateSites() error {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM sites WHERE slug = ?`, DefaultSiteSlug).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		// The console hostname an install already advertises becomes the
		// default site's console, so nothing has to be reconfigured.
		var host string
		_ = s.db.QueryRow(`SELECT value FROM settings WHERE key = 'base_domain'`).Scan(&host)
		res, cerr := s.db.Exec(`INSERT INTO sites(slug, name, console_host, enabled, created_at)
			VALUES(?, 'Default', ?, 1, ?)`, DefaultSiteSlug, NormalizeHost(host), stamp(time.Now()))
		if cerr != nil {
			return fmt.Errorf("create default site: %w", cerr)
		}
		if id, cerr = res.LastInsertId(); cerr != nil {
			return cerr
		}
	} else if err != nil {
		return fmt.Errorf("read default site: %w", err)
	}
	for _, table := range scopedTables {
		if merge, ok := adoptMerges[table]; ok {
			if _, err := s.db.Exec(merge, id, id); err != nil {
				return fmt.Errorf("merge %s rows: %w", table, err)
			}
		}
		if _, err := s.db.Exec(`UPDATE `+table+` SET site_id = ? WHERE site_id = 0`, id); err != nil {
			return fmt.Errorf("adopt %s rows: %w", table, err)
		}
	}
	// From here on the plain handle is the default site's, so every existing
	// caller keeps seeing exactly the rows it saw before sites existed.
	s.site = id
	s.defaultSite = id
	// Bans are per site: the same address may be banned on one host and
	// allowed on another, so the key is the pair.
	if _, err := s.db.Exec(`DROP INDEX IF EXISTS idx_bans_cidr`); err != nil {
		return err
	}
	if _, err := s.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_bans_site_cidr ON bans(site_id, cidr)`); err != nil {
		return err
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_proxies_site ON proxies(site_id)`); err != nil {
		return err
	}
	// A saved log view's name is only unique inside its site. Older databases
	// key on the name alone, so the table is rebuilt once.
	var keyed int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('log_views')
		WHERE name = 'site_id' AND pk > 0`).Scan(&keyed); err != nil {
		return err
	}
	if keyed == 0 {
		if _, err := s.db.Exec(`CREATE TABLE log_views_sites (
			name TEXT NOT NULL,
			query TEXT NOT NULL,
			updated_by TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL,
			site_id INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY(site_id, name)
		)`); err != nil {
			return err
		}
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO log_views_sites(name, query, updated_by, updated_at, site_id)
			SELECT name, query, updated_by, updated_at, site_id FROM log_views`); err != nil {
			return err
		}
		if _, err := s.db.Exec(`DROP TABLE log_views`); err != nil {
			return err
		}
		if _, err := s.db.Exec(`ALTER TABLE log_views_sites RENAME TO log_views`); err != nil {
			return err
		}
	}
	return nil
}

// SiteForHost resolves a console hostname to the site that owns it. A host no
// site and no proxy claims, and a single-site install, both land on the default
// site, so the console reached the way it always was is unchanged.
func (s *Store) SiteForHost(host string) int64 {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		return s.defaultSite
	}
	var id int64
	if err := s.db.QueryRow(`SELECT id FROM sites WHERE lower(console_host) = ?`, host).Scan(&id); err == nil {
		return id
	}
	var site int64
	if err := s.db.QueryRow(`SELECT site_id FROM proxies WHERE lower(hostname) = ?`, host).Scan(&site); err == nil && site != 0 {
		return site
	}
	return s.defaultSite
}

func isUniqueErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
