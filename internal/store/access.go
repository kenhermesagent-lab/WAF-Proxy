package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// GateSessionRef derives the stable, non-reversible reference exposed for a
// visitor session. The session cookie itself is the database key and must never
// leave the proxy, so callers address sessions by this hash instead.
func GateSessionRef(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:16])
}

// AddUsernameBan blocks a gate username. A permanent row wins over a temporary
// one, matching the IP ban behaviour. The block is replicated, so a username
// banned just before a failover stays banned.
func (s *Store) AddUsernameBan(username, reason, createdBy string, expires *time.Time) error {
	return s.upsertChanged("username_bans", []string{"username"}, func(db execer) ([]any, error) {
		_, err := db.Exec(`INSERT INTO username_bans(username, reason, created_by, created_at, expires_at, site_id)
			VALUES(?, ?, ?, ?, ?, ?)
			ON CONFLICT(username) DO UPDATE SET
				reason = excluded.reason,
				created_by = excluded.created_by,
				created_at = excluded.created_at,
				expires_at = CASE
					WHEN excluded.expires_at IS NULL OR username_bans.expires_at IS NULL THEN NULL
					ELSE excluded.expires_at END`,
			username, reason, createdBy, stamp(time.Now()), nullTime(expires), s.site)
		return []any{username}, err
	})
}

// UsernameBanned reports whether a username is currently blocked.
func (s *Store) UsernameBanned(username string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM username_bans
		WHERE username = ? AND (expires_at IS NULL OR expires_at > ?) AND (? = 0 OR site_id = ?)`,
		username, stamp(time.Now()), s.site, s.site).Scan(&n)
	return n > 0, err
}

// ListUsernameBans returns username blocks, optionally including expired ones.
func (s *Store) ListUsernameBans(includeExpired bool) ([]model.UsernameBan, error) {
	q := `SELECT username, reason, created_by, created_at, expires_at FROM username_bans
		WHERE (? = 0 OR site_id = ?)`
	args := []any{s.site, s.site}
	if !includeExpired {
		q += ` AND (expires_at IS NULL OR expires_at > ?)`
		args = append(args, stamp(time.Now()))
	}
	q += ` ORDER BY username`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.UsernameBan{}
	for rows.Next() {
		var b model.UsernameBan
		var created string
		var expires sql.NullString
		if err := rows.Scan(&b.Username, &b.Reason, &b.CreatedBy, &created, &expires); err != nil {
			return nil, err
		}
		b.CreatedAt = parseStamp(created)
		b.ExpiresAt = parseStampPtr(expires)
		out = append(out, b)
	}
	return out, rows.Err()
}

// RemoveUsernameBan lifts a username block and reports whether one existed.
func (s *Store) RemoveUsernameBan(username string) (bool, error) {
	n, err := s.deleteCaptured("username_bans", []string{"username"}, `username = ? AND (? = 0 OR site_id = ?)`, username, s.site, s.site)
	return n > 0, err
}

// GateSessions returns live visitor sessions newest first. Expired rows are
// omitted; the retention loop removes them eventually.
func (s *Store) GateSessions(limit int) ([]model.GateSession, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	rows, err := s.db.Query(`SELECT gs.id, gs.proxy_id, COALESCE(p.hostname, ''), gs.username,
		gs.ip, gs.ua, gs.created_at, gs.expires_at
		FROM gate_sessions gs LEFT JOIN proxies p ON p.id = gs.proxy_id
		WHERE gs.expires_at > ? AND (? = 0 OR gs.site_id = ?) ORDER BY gs.created_at DESC LIMIT ?`, stamp(time.Now()), s.site, s.site, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.GateSession{}
	for rows.Next() {
		var id, created, expires string
		var s model.GateSession
		if err := rows.Scan(&id, &s.ProxyID, &s.ProxyHostname, &s.Username, &s.IP, &s.UA, &created, &expires); err != nil {
			return nil, err
		}
		s.ID = id
		s.Ref = GateSessionRef(id)
		s.CreatedAt = parseStamp(created)
		s.ExpiresAt = parseStamp(expires)
		out = append(out, s)
	}
	return out, rows.Err()
}

// DeleteGateSessionByRef revokes one live session by its public reference.
func (s *Store) DeleteGateSessionByRef(ref string) (*model.GateSession, error) {
	sessions, err := s.GateSessions(1000)
	if err != nil {
		return nil, err
	}
	for i := range sessions {
		if sessions[i].Ref != ref {
			continue
		}
		if _, err := s.deleteCaptured("gate_sessions", []string{"id"}, `id = ? AND (? = 0 OR site_id = ?)`, sessions[i].ID, s.site, s.site); err != nil {
			return nil, err
		}
		return &sessions[i], nil
	}
	return nil, ErrNotFound
}

// DeleteGateSessionsForIP revokes every live session opened from an address.
func (s *Store) DeleteGateSessionsForIP(ip string) (int64, error) {
	return s.deleteCaptured("gate_sessions", []string{"id"}, `ip = ? AND (? = 0 OR site_id = ?)`, ip, s.site, s.site)
}

// CountGateSessions reports how many live visitor sessions exist.
func (s *Store) CountGateSessions() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM gate_sessions WHERE expires_at > ? AND (? = 0 OR site_id = ?)`, stamp(time.Now()), s.site, s.site).Scan(&n)
	return n, err
}

// CreateMCPToken stores a hashed agent credential and its tool scopes.
func (s *Store) CreateMCPToken(name, hash, prefix, createdBy string, scopes []string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO mcp_tokens(name, token_hash, prefix, created_by, created_at, scopes, site_id)
		VALUES(?, ?, ?, ?, ?, ?, ?)`, name, hash, prefix, createdBy, stamp(time.Now()), strings.Join(scopes, ","), s.site)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListMCPTokens returns every agent credential, active first.
func (s *Store) ListMCPTokens() ([]model.MCPToken, error) {
	rows, err := s.db.Query(`SELECT t.id, t.name, t.prefix, t.created_by, t.created_at, t.last_used_at, t.revoked_at, t.scopes, t.site_id, COALESCE(sites.slug, '')
		FROM mcp_tokens t LEFT JOIN sites ON sites.id = t.site_id
		WHERE (? = 0 OR t.site_id = ?) ORDER BY t.revoked_at IS NOT NULL, t.id DESC LIMIT 200`, s.site, s.site)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.MCPToken{}
	for rows.Next() {
		var t model.MCPToken
		var created, scopes string
		var lastUsed, revoked sql.NullString
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &t.CreatedBy, &created, &lastUsed, &revoked, &scopes, &t.SiteID, &t.Site); err != nil {
			return nil, err
		}
		t.CreatedAt = parseStamp(created)
		t.LastUsedAt = parseStampPtr(lastUsed)
		t.RevokedAt = parseStampPtr(revoked)
		t.Scopes = splitScopes(scopes)
		out = append(out, t)
	}
	return out, rows.Err()
}

// MCPTokenByHash loads an active agent credential.
func (s *Store) MCPTokenByHash(hash string) (*model.MCPToken, error) {
	var t model.MCPToken
	var created, scopes string
	var lastUsed, revoked sql.NullString
	err := s.db.QueryRow(`SELECT t.id, t.name, t.prefix, t.created_by, t.created_at, t.last_used_at, t.revoked_at, t.scopes, t.site_id, COALESCE(sites.slug, '')
		FROM mcp_tokens t LEFT JOIN sites ON sites.id = t.site_id
		WHERE t.token_hash = ? AND t.revoked_at IS NULL AND (? = 0 OR t.site_id = ?)`, hash, s.site, s.site).
		Scan(&t.ID, &t.Name, &t.Prefix, &t.CreatedBy, &created, &lastUsed, &revoked, &scopes, &t.SiteID, &t.Site)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.CreatedAt = parseStamp(created)
	t.LastUsedAt = parseStampPtr(lastUsed)
	t.RevokedAt = parseStampPtr(revoked)
	t.Scopes = splitScopes(scopes)
	return &t, nil
}

func splitScopes(raw string) []string {
	if raw == "" {
		return []string{}
	}
	return strings.Split(raw, ",")
}

// TouchMCPToken records a successful authenticated call without failing the
// request when the best-effort write is lost.
func (s *Store) TouchMCPToken(id int64) error {
	_, err := s.db.Exec(`UPDATE mcp_tokens SET last_used_at = ? WHERE id = ? AND (? = 0 OR site_id = ?)`, stamp(time.Now()), id, s.site, s.site)
	return err
}

// RevokeMCPToken disables a credential and reports whether it was active.
func (s *Store) RevokeMCPToken(id int64) (bool, error) {
	res, err := s.db.Exec(`UPDATE mcp_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL AND (? = 0 OR site_id = ?)`,
		stamp(time.Now()), id, s.site, s.site)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
