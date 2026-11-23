package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// ListPolicies returns every policy ordered by priority.
func (s *Store) ListPolicies() ([]model.Policy, error) {
	rows, err := s.db.Query(`SELECT id, scope, proxy_id, kind, value, action, priority, enabled, note
		FROM policies WHERE (? = 0 OR site_id = ?) ORDER BY priority ASC, id`, s.site, s.site)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Policy{}
	for rows.Next() {
		var p model.Policy
		var proxyID sql.NullInt64
		var enabled int
		if err := rows.Scan(&p.ID, &p.Scope, &proxyID, &p.Kind, &p.Value, &p.Action, &p.Priority, &enabled, &p.Note); err != nil {
			return nil, err
		}
		if proxyID.Valid {
			p.ProxyID = &proxyID.Int64
		}
		p.Enabled = i2b(enabled)
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPolicy loads one policy.
func (s *Store) GetPolicy(id int64) (*model.Policy, error) {
	var p model.Policy
	var proxyID sql.NullInt64
	var enabled int
	err := s.db.QueryRow(`SELECT id, scope, proxy_id, kind, value, action, priority, enabled, note
		FROM policies WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site).
		Scan(&p.ID, &p.Scope, &proxyID, &p.Kind, &p.Value, &p.Action, &p.Priority, &enabled, &p.Note)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if proxyID.Valid {
		p.ProxyID = &proxyID.Int64
	}
	p.Enabled = i2b(enabled)
	return &p, nil
}

// CreatePolicy inserts a policy.
func (s *Store) CreatePolicy(p *model.Policy) (int64, error) {
	if p.Priority == 0 {
		p.Priority = 100
	}
	if p.Action == "" {
		p.Action = "block"
	}
	res, err := s.db.Exec(`INSERT INTO policies(scope, proxy_id, kind, value, action, priority, enabled, note, site_id)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`, p.Scope, p.ProxyID, p.Kind, p.Value, p.Action, p.Priority, b2i(p.Enabled), p.Note, s.site)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdatePolicy writes an existing policy.
func (s *Store) UpdatePolicy(p *model.Policy) error {
	_, err := s.db.Exec(`UPDATE policies SET scope = ?, proxy_id = ?, kind = ?, value = ?, action = ?,
		priority = ?, enabled = ?, note = ? WHERE id = ? AND (? = 0 OR site_id = ?)`,
		p.Scope, p.ProxyID, p.Kind, p.Value, p.Action, p.Priority, b2i(p.Enabled), p.Note, p.ID, s.site, s.site)
	return err
}

// DeletePolicy removes a policy.
func (s *Store) DeletePolicy(id int64) error {
	_, err := s.db.Exec(`DELETE FROM policies WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site)
	return err
}

// ListBans returns bans, optionally including expired ones.
func (s *Store) ListBans(includeExpired bool) ([]model.Ban, error) {
	q := `SELECT id, cidr, reason, source, permanent, hits, created_by, created_at, expires_at FROM bans
		WHERE (? = 0 OR site_id = ?)`
	args := []any{s.site, s.site}
	if !includeExpired {
		q += ` AND (permanent = 1 OR expires_at IS NULL OR expires_at > ?)`
		args = append(args, stamp(time.Now()))
	}
	q += ` ORDER BY id DESC LIMIT 2000`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Ban{}
	for rows.Next() {
		var b model.Ban
		var permanent int
		var created string
		var expires sql.NullString
		if err := rows.Scan(&b.ID, &b.CIDR, &b.Reason, &b.Source, &permanent, &b.Hits, &b.CreatedBy, &created, &expires); err != nil {
			return nil, err
		}
		b.Permanent = i2b(permanent)
		b.CreatedAt = parseStamp(created)
		b.ExpiresAt = parseStampPtr(expires)
		out = append(out, b)
	}
	return out, rows.Err()
}

// BanByID loads a single ban, including an expired one. The dashboard list is
// capped, so mutations must resolve the row directly instead of scanning it.
func (s *Store) BanByID(id int64) (*model.Ban, error) {
	return scanBan(s.db.QueryRow(`SELECT id, cidr, reason, source, permanent, hits, created_by, created_at, expires_at
		FROM bans WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site))
}

// BanByCIDR loads a single ban by its CIDR.
func (s *Store) BanByCIDR(cidr string) (*model.Ban, error) {
	return scanBan(s.db.QueryRow(`SELECT id, cidr, reason, source, permanent, hits, created_by, created_at, expires_at
		FROM bans WHERE cidr = ? AND (? = 0 OR site_id = ?)`, cidr, s.site, s.site))
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanBan(row rowScanner) (*model.Ban, error) {
	var b model.Ban
	var permanent int
	var created string
	var expires sql.NullString
	err := row.Scan(&b.ID, &b.CIDR, &b.Reason, &b.Source, &permanent, &b.Hits, &b.CreatedBy, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	b.Permanent = i2b(permanent)
	b.CreatedAt = parseStamp(created)
	b.ExpiresAt = parseStampPtr(expires)
	return &b, nil
}

// AddBan inserts a ban, or refreshes the reason and expiry of an existing CIDR.
func (s *Store) AddBan(b *model.Ban) (int64, error) {
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now()
	}
	res, err := s.db.Exec(`INSERT INTO bans(cidr, reason, source, permanent, hits, created_by, created_at, expires_at, site_id)
		VALUES(?, ?, ?, ?, 0, ?, ?, ?, ?)
		ON CONFLICT(site_id, cidr) DO UPDATE SET
			reason = excluded.reason,
			source = excluded.source,
			permanent = MAX(bans.permanent, excluded.permanent),
			expires_at = CASE
				WHEN excluded.permanent = 1 OR bans.permanent = 1 THEN NULL
				ELSE excluded.expires_at END`,
		b.CIDR, b.Reason, b.Source, b2i(b.Permanent), b.CreatedBy, stamp(b.CreatedAt), nullTime(b.ExpiresAt), s.site)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	if id == 0 {
		_ = s.db.QueryRow(`SELECT id FROM bans WHERE cidr = ? AND site_id = ?`, b.CIDR, s.site).Scan(&id)
	}
	return id, nil
}

// DeleteBan removes a ban by ID.
func (s *Store) DeleteBan(id int64) error {
	_, err := s.db.Exec(`DELETE FROM bans WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site)
	return err
}

// DeleteBanByCIDR removes a ban by CIDR and reports whether a row was deleted.
func (s *Store) DeleteBanByCIDR(cidr string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM bans WHERE cidr = ? AND (? = 0 OR site_id = ?)`, cidr, s.site, s.site)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// PromoteBan makes a ban permanent.
func (s *Store) PromoteBan(id int64) error {
	_, err := s.db.Exec(`UPDATE bans SET permanent = 1, expires_at = NULL WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site)
	return err
}

// DemoteBan turns a permanent ban back into a temporary one that expires at the
// given time.
func (s *Store) DemoteBan(id int64, expires time.Time) error {
	_, err := s.db.Exec(`UPDATE bans SET permanent = 0, expires_at = ? WHERE id = ? AND (? = 0 OR site_id = ?)`, stamp(expires), id, s.site, s.site)
	return err
}

// AddBanHits adds n to the hit counter of a CIDR.
func (s *Store) AddBanHits(cidr string, n int64) {
	if n <= 0 {
		return
	}
	_, _ = s.db.Exec(`UPDATE bans SET hits = hits + ? WHERE cidr = ? AND (? = 0 OR site_id = ?)`, n, cidr, s.site, s.site)
}

// PurgeBans removes expired temporary bans.
func (s *Store) PurgeBans() error {
	_, err := s.db.Exec(`DELETE FROM bans WHERE permanent = 0 AND expires_at IS NOT NULL AND expires_at <= ? AND (? = 0 OR site_id = ?)`, stamp(time.Now()), s.site, s.site)
	return err
}

// ListFeeds returns all feeds.
func (s *Store) ListFeeds() ([]model.Feed, error) {
	rows, err := s.db.Query(`SELECT id, name, url, action, interval_s, enabled, builtin, local, always_block, filename,
		local_path, etag, last_modified, last_fetch, last_count, state, last_error FROM feeds
		WHERE (site_id = 0 OR site_id = ?) ORDER BY id`, s.site)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Feed{}
	for rows.Next() {
		var f model.Feed
		var enabled, builtin, local, always int
		var lastFetch sql.NullString
		if err := rows.Scan(&f.ID, &f.Name, &f.URL, &f.Action, &f.IntervalS, &enabled, &builtin, &local, &always,
			&f.Filename, &f.LocalPath, &f.ETag, &f.LastModified, &lastFetch, &f.LastCount, &f.State, &f.LastError); err != nil {
			return nil, err
		}
		f.Enabled = i2b(enabled)
		f.Builtin = i2b(builtin)
		f.Local = i2b(local)
		f.AlwaysBlock = i2b(always)
		f.LastFetch = parseStampPtr(lastFetch)
		out = append(out, f)
	}
	return out, rows.Err()
}

// FeedByID loads one feed. The API needs the local path before deleting the row
// so an uploaded file is not left behind in the data directory.
func (s *Store) FeedByID(id int64) (*model.Feed, error) {
	var f model.Feed
	var enabled, builtin, local, always int
	var lastFetch sql.NullString
	err := s.db.QueryRow(`SELECT id, name, url, action, interval_s, enabled, builtin, local, always_block, filename,
		local_path, etag, last_modified, last_fetch, last_count, state, last_error
		FROM feeds WHERE id = ? AND (site_id = 0 OR site_id = ?)`, id, s.site).Scan(&f.ID, &f.Name, &f.URL, &f.Action, &f.IntervalS, &enabled, &builtin,
		&local, &always, &f.Filename, &f.LocalPath, &f.ETag, &f.LastModified, &lastFetch, &f.LastCount, &f.State, &f.LastError)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	f.Enabled = i2b(enabled)
	f.Builtin = i2b(builtin)
	f.Local = i2b(local)
	f.AlwaysBlock = i2b(always)
	f.LastFetch = parseStampPtr(lastFetch)
	return &f, nil
}

// UpdateFeedFetch records the result of a feed refresh.
func (s *Store) UpdateFeedFetch(id int64, etag, lastModified string, count int, state, lastErr string) error {
	_, err := s.db.Exec(`UPDATE feeds SET etag = ?, last_modified = ?, last_fetch = ?, last_count = ?,
		state = ?, last_error = ? WHERE id = ? AND (? = 0 OR site_id = ?)`,
		etag, lastModified, stamp(time.Now()), count, state, lastErr, id, s.site, s.site)
	return err
}

// UpdateFeed writes operator-editable feed fields. The source URL is fixed at
// creation so a local upload cannot be redirected to a remote fetch.
func (s *Store) UpdateFeed(f *model.Feed) error {
	_, err := s.db.Exec(`UPDATE feeds SET action = ?, interval_s = ?, enabled = ? WHERE id = ? AND site_id = ?`,
		f.Action, f.IntervalS, b2i(f.Enabled), f.ID, s.site)
	return err
}

// CreateFeed inserts a custom feed.
func (s *Store) CreateFeed(f *model.Feed) (int64, error) {
	if f.Action == "" {
		f.Action = "block"
	}
	if f.IntervalS <= 0 {
		f.IntervalS = 900
	}
	res, err := s.db.Exec(`INSERT INTO feeds(name, url, action, interval_s, enabled, builtin, local, always_block, filename, local_path, state, site_id)
		VALUES(?, ?, ?, ?, ?, 0, ?, ?, ?, ?, 'pending', ?)`, f.Name, f.URL, f.Action, f.IntervalS, b2i(f.Enabled),
		b2i(f.Local), b2i(f.AlwaysBlock), f.Filename, f.LocalPath, s.site)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// DeleteFeed removes a custom feed and reports whether a row was deleted, so a
// built-in feed is not confused with a database failure.
func (s *Store) DeleteFeed(id int64) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM feeds WHERE id = ? AND builtin = 0 AND site_id = ?`, id, s.site)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (s *Store) seedFeeds() error {
	type seed struct {
		name, url, action string
		interval          int
		enabled           bool
	}
	builtins := []seed{
		{"FireHOL level 1", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "block", 900, true},
		{"Spamhaus DROP", "https://www.spamhaus.org/drop/drop.txt", "block", 3600, true},
		{"Tor exit nodes", "https://check.torproject.org/torbulkexitlist", "challenge", 3600, true},
		{"FireHOL level 2", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset", "block", 1800, false},
		{"Feodo Tracker C2", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "block", 1800, false},
		{"ET compromised", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "block", 3600, false},
		{"DShield scanners", "https://feeds.dshield.org/block.txt", "block", 1800, false},
		// Keyless lists that need no account; disabled until an operator turns
		// them on, so an upgrade does not start blocking new ranges by itself.
		{"Blocklist.de attackers", "https://lists.blocklist.de/lists/all.txt", "block", 3600, false},
		{"GreenSnow blocklist", "https://blocklist.greensnow.co/greensnow.txt", "block", 3600, false},
		{"Binary Defense banlist", "https://www.binarydefense.com/banlist.txt", "block", 3600, false},
		{"CINS Army", "https://cinsscore.com/list/ci-badguys.txt", "block", 3600, false},
		{"BruteForceBlocker", "https://danger.rulez.sk/projects/bruteforceblocker/blist.php", "block", 3600, false},
		{"IPSum level 3", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", "block", 3600, false},
		{"Spamhaus DROP IPv6", "https://www.spamhaus.org/drop/dropv6.txt", "block", 3600, false},
		{"ET firewall block list", "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt", "block", 3600, false},
	}
	for _, b := range builtins {
		if _, err := s.db.Exec(`INSERT INTO feeds(name, url, action, interval_s, enabled, builtin, state)
			VALUES(?, ?, ?, ?, ?, 1, 'pending')
			ON CONFLICT(name) DO NOTHING`, b.name, b.url, b.action, b.interval, b2i(b.enabled)); err != nil {
			return err
		}
	}
	// EDROP was folded into DROP (the feed file is now a header-only stub) and
	// URLhaus needs an Auth-Key, so its public export answers 410 Gone. Drop the
	// rows older releases seeded; a custom feed with the same name is kept.
	if _, err := s.db.Exec(`DELETE FROM feeds WHERE builtin = 1 AND name IN ('Spamhaus EDROP', 'URLhaus hosts')`); err != nil {
		return err
	}
	return nil
}

// EnqueueAlert stores a notification for delivery.
func (s *Store) EnqueueAlert(channel, kind, dedupe, payload string) error {
	return s.EnqueueAlertState(channel, kind, dedupe, payload, "pending")
}

// EnqueueAlertState stores a notification with an explicit state.
func (s *Store) EnqueueAlertState(channel, kind, dedupe, payload, state string) error {
	_, err := s.db.Exec(`INSERT INTO alerts(channel, kind, dedupe, payload, state, created_at, site_id)
		VALUES(?, ?, ?, ?, ?, ?, ?)`, channel, kind, dedupe, payload, state, stamp(time.Now()), s.site)
	return err
}

// AlertRecentlySent reports whether a dedupe key was delivered since a time.
func (s *Store) AlertRecentlySent(dedupe string, since time.Time) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE dedupe = ? AND created_at > ? AND state IN ('sent','pending','immediate') AND (? = 0 OR site_id = ?)`,
		dedupe, stamp(since), s.site, s.site).Scan(&n)
	return n > 0, err
}

// PendingAlerts returns unsent alerts in order.
func (s *Store) PendingAlerts(limit int) ([]model.Alert, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id, channel, kind, dedupe, payload, state, attempts, created_at, sent_at
		FROM alerts WHERE state IN ('pending','immediate') AND (? = 0 OR site_id = ?) ORDER BY id LIMIT ?`, s.site, s.site, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Alert{}
	for rows.Next() {
		var a model.Alert
		var created string
		var sent sql.NullString
		if err := rows.Scan(&a.ID, &a.Channel, &a.Kind, &a.Dedupe, &a.Payload, &a.State, &a.Attempts, &created, &sent); err != nil {
			return nil, err
		}
		a.CreatedAt = parseStamp(created)
		a.SentAt = parseStampPtr(sent)
		out = append(out, a)
	}
	return out, rows.Err()
}

// MarkAlert records delivery success or failure.
func (s *Store) MarkAlert(id int64, state string, attempts int) error {
	_, err := s.db.Exec(`UPDATE alerts SET state = ?, attempts = ?, sent_at = ? WHERE id = ? AND (? = 0 OR site_id = ?)`,
		state, attempts, stamp(time.Now()), id, s.site, s.site)
	return err
}

// RecentAlerts returns the most recent notification attempts.
func (s *Store) RecentAlerts(limit int) ([]model.Alert, error) {
	rows, err := s.db.Query(`SELECT id, channel, kind, dedupe, payload, state, attempts, created_at, sent_at
		FROM alerts WHERE (? = 0 OR site_id = ?) ORDER BY id DESC LIMIT ?`, s.site, s.site, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Alert{}
	for rows.Next() {
		var a model.Alert
		var created string
		var sent sql.NullString
		if err := rows.Scan(&a.ID, &a.Channel, &a.Kind, &a.Dedupe, &a.Payload, &a.State, &a.Attempts, &created, &sent); err != nil {
			return nil, err
		}
		a.CreatedAt = parseStamp(created)
		a.SentAt = parseStampPtr(sent)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---------- access gate ----------

// ListGateUsers returns all gate accounts.
func (s *Store) ListGateUsers() ([]model.GateUser, error) {
	rows, err := s.db.Query(`SELECT id, username, password_hash, totp_secret, totp_enabled, created_at
		FROM gate_users WHERE (? = 0 OR site_id = ?) ORDER BY username`, s.site, s.site)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.GateUser{}
	for rows.Next() {
		var u model.GateUser
		var enabled int
		var created string
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.TOTPSecret, &enabled, &created); err != nil {
			return nil, err
		}
		u.TOTPEnabled = i2b(enabled)
		u.CreatedAt = parseStamp(created)
		out = append(out, u)
	}
	return out, rows.Err()
}

// GateUserByUsername loads a gate account.
func (s *Store) GateUserByUsername(username string) (*model.GateUser, error) {
	var u model.GateUser
	var enabled int
	var created string
	err := s.db.QueryRow(`SELECT id, username, password_hash, totp_secret, totp_enabled, created_at
		FROM gate_users WHERE username = ? AND (? = 0 OR site_id = ?)`, username, s.site, s.site).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.TOTPSecret, &enabled, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.TOTPEnabled = i2b(enabled)
	u.CreatedAt = parseStamp(created)
	return &u, nil
}

// CreateGateUser inserts a gate account.
func (s *Store) CreateGateUser(username, hash, totpSecret string, totpEnabled bool) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO gate_users(username, password_hash, totp_secret, totp_enabled, created_at, site_id)
		VALUES(?, ?, ?, ?, ?, ?)`, username, hash, totpSecret, b2i(totpEnabled), stamp(time.Now()), s.site)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateGateUser updates a gate account's secret material.
func (s *Store) UpdateGateUser(id int64, hash, totpSecret string, totpEnabled bool) error {
	_, err := s.db.Exec(`UPDATE gate_users SET password_hash = ?, totp_secret = ?, totp_enabled = ? WHERE id = ? AND (? = 0 OR site_id = ?)`,
		hash, totpSecret, b2i(totpEnabled), id, s.site, s.site)
	return err
}

// DeleteGateUser removes a gate account together with its ACL rows and visitor
// sessions. Leaving the sessions behind would keep a deleted account logged in
// until they expired.
func (s *Store) DeleteGateUser(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var username string
	if err := tx.QueryRow(`SELECT username FROM gate_users WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site).Scan(&username); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if _, err := tx.Exec(`DELETE FROM gate_sessions WHERE username = ? AND (? = 0 OR site_id = ?)`,
		username, s.site, s.site); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM gate_acl WHERE username = ?`, username); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM gate_users WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteGateSessionsFor ends every visitor session of one gate account, which is
// what a password change requires.
func (s *Store) DeleteGateSessionsFor(username string) error {
	_, err := s.RevokeGateSessionsFor(username)
	return err
}

// RevokeGateSessionsFor ends every visitor session of one gate account and
// reports how many were removed, so an agent can show the effect of a block.
func (s *Store) RevokeGateSessionsFor(username string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM gate_sessions WHERE username = ? AND (? = 0 OR site_id = ?)`, username, s.site, s.site)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// SetGateACL replaces the accounts allowed through one proxy.
func (s *Store) SetGateACL(proxyID int64, usernames []string) error {
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
	if _, err := tx.Exec(`DELETE FROM gate_acl WHERE proxy_id = ?`, proxyID); err != nil {
		return err
	}
	for _, u := range usernames {
		if _, err := tx.Exec(`INSERT INTO gate_acl(proxy_id, username) VALUES(?, ?)`, proxyID, u); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GateACL returns the accounts allowed through one proxy.
func (s *Store) GateACL(proxyID int64) ([]string, error) {
	if ok, err := s.ownsProxy(proxyID); err != nil {
		return nil, err
	} else if !ok {
		return nil, ErrNotFound
	}
	rows, err := s.db.Query(`SELECT username FROM gate_acl WHERE proxy_id = ? ORDER BY username`, proxyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CreateGateSession stores a visitor session.
func (s *Store) CreateGateSession(id string, proxyID int64, username, ip, ua string, expires time.Time) error {
	_, err := s.db.Exec(`INSERT INTO gate_sessions(id, proxy_id, username, ip, ua, created_at, expires_at, site_id)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, id, proxyID, username, ip, ua, stamp(time.Now()), stamp(expires), s.site)
	return err
}

// LookupGateSession returns a live visitor session. A username blocked after
// the session was issued is treated as signed out even if a revocation write
// was lost.
func (s *Store) LookupGateSession(id string, proxyID int64) (string, bool) {
	var username string
	now := stamp(time.Now())
	err := s.db.QueryRow(`SELECT gs.username FROM gate_sessions gs
		WHERE gs.id = ? AND gs.proxy_id = ? AND gs.expires_at > ? AND (? = 0 OR gs.site_id = ?)
		AND NOT EXISTS (SELECT 1 FROM username_bans ub
			WHERE ub.username = gs.username AND (ub.expires_at IS NULL OR ub.expires_at > ?))`,
		id, proxyID, now, s.site, s.site, now).Scan(&username)
	if err != nil {
		return "", false
	}
	return username, true
}

// DeleteGateSession removes a visitor session.
func (s *Store) DeleteGateSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM gate_sessions WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site)
	return err
}

// DeleteProxyGateSessions revokes every session for a proxy.
func (s *Store) DeleteProxyGateSessions(proxyID int64) error {
	_, err := s.db.Exec(`DELETE FROM gate_sessions WHERE proxy_id = ? AND (? = 0 OR site_id = ?)`, proxyID, s.site, s.site)
	return err
}

// CountBans reports how many bans match the same filter as ListBansPage, so
// the API can say whether a page is a sample of a longer list.
func (s *Store) CountBans(includeExpired bool) (int, error) {
	q := `SELECT COUNT(*) FROM bans WHERE (? = 0 OR site_id = ?)`
	args := []any{s.site, s.site}
	if !includeExpired {
		q += ` AND (permanent = 1 OR expires_at IS NULL OR expires_at > ?)`
		args = append(args, stamp(time.Now()))
	}
	var n int
	err := s.db.QueryRow(q, args...).Scan(&n)
	return n, err
}

// ListBansPage returns the newest bans for the dashboard. The engine loads the
// full set through ListBans; only the API view is capped so the list an
// operator reads stays short no matter how many addresses were ever banned.
func (s *Store) ListBansPage(includeExpired bool, limit int) ([]model.Ban, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := `SELECT id, cidr, reason, source, permanent, hits, created_by, created_at, expires_at FROM bans
		WHERE (? = 0 OR site_id = ?)`
	args := []any{s.site, s.site}
	if !includeExpired {
		q += ` AND (permanent = 1 OR expires_at IS NULL OR expires_at > ?)`
		args = append(args, stamp(time.Now()))
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Ban{}
	for rows.Next() {
		var b model.Ban
		var permanent int
		var created string
		var expires sql.NullString
		if err := rows.Scan(&b.ID, &b.CIDR, &b.Reason, &b.Source, &permanent, &b.Hits, &b.CreatedBy, &created, &expires); err != nil {
			return nil, err
		}
		b.Permanent = i2b(permanent)
		b.CreatedAt = parseStamp(created)
		b.ExpiresAt = parseStampPtr(expires)
		out = append(out, b)
	}
	return out, rows.Err()
}
