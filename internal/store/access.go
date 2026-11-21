package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
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
// one, matching the IP ban behaviour.
func (s *Store) AddUsernameBan(username, reason, createdBy string, expires *time.Time) error {
	_, err := s.db.Exec(`INSERT INTO username_bans(username, reason, created_by, created_at, expires_at)
		VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
			reason = excluded.reason,
			created_by = excluded.created_by,
			created_at = excluded.created_at,
			expires_at = CASE
				WHEN excluded.expires_at IS NULL OR username_bans.expires_at IS NULL THEN NULL
				ELSE excluded.expires_at END`,
		username, reason, createdBy, stamp(time.Now()), nullTime(expires))
	return err
}

// UsernameBanned reports whether a username is currently blocked.
func (s *Store) UsernameBanned(username string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM username_bans
		WHERE username = ? AND (expires_at IS NULL OR expires_at > ?)`,
		username, stamp(time.Now())).Scan(&n)
	return n > 0, err
}

// ListUsernameBans returns username blocks, optionally including expired ones.
func (s *Store) ListUsernameBans(includeExpired bool) ([]model.UsernameBan, error) {
	q := `SELECT username, reason, created_by, created_at, expires_at FROM username_bans`
	args := []any{}
	if !includeExpired {
		q += ` WHERE expires_at IS NULL OR expires_at > ?`
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
	res, err := s.db.Exec(`DELETE FROM username_bans WHERE username = ?`, username)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
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
		WHERE gs.expires_at > ? ORDER BY gs.created_at DESC LIMIT ?`, stamp(time.Now()), limit)
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
		if _, err := s.db.Exec(`DELETE FROM gate_sessions WHERE id = ?`, sessions[i].ID); err != nil {
			return nil, err
		}
		return &sessions[i], nil
	}
	return nil, ErrNotFound
}

// DeleteGateSessionsForIP revokes every live session opened from an address.
func (s *Store) DeleteGateSessionsForIP(ip string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM gate_sessions WHERE ip = ?`, ip)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CountGateSessions reports how many live visitor sessions exist.
func (s *Store) CountGateSessions() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM gate_sessions WHERE expires_at > ?`, stamp(time.Now())).Scan(&n)
	return n, err
}

// CreateMCPToken stores a hashed agent credential.
func (s *Store) CreateMCPToken(name, hash, prefix, createdBy string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO mcp_tokens(name, token_hash, prefix, created_by, created_at)
		VALUES(?, ?, ?, ?, ?)`, name, hash, prefix, createdBy, stamp(time.Now()))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListMCPTokens returns every agent credential, active first.
func (s *Store) ListMCPTokens() ([]model.MCPToken, error) {
	rows, err := s.db.Query(`SELECT id, name, prefix, created_by, created_at, last_used_at, revoked_at
		FROM mcp_tokens ORDER BY revoked_at IS NOT NULL, id DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.MCPToken{}
	for rows.Next() {
		var t model.MCPToken
		var created string
		var lastUsed, revoked sql.NullString
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &t.CreatedBy, &created, &lastUsed, &revoked); err != nil {
			return nil, err
		}
		t.CreatedAt = parseStamp(created)
		t.LastUsedAt = parseStampPtr(lastUsed)
		t.RevokedAt = parseStampPtr(revoked)
		out = append(out, t)
	}
	return out, rows.Err()
}

// MCPTokenByHash loads an active agent credential.
func (s *Store) MCPTokenByHash(hash string) (*model.MCPToken, error) {
	var t model.MCPToken
	var created string
	var lastUsed, revoked sql.NullString
	err := s.db.QueryRow(`SELECT id, name, prefix, created_by, created_at, last_used_at, revoked_at
		FROM mcp_tokens WHERE token_hash = ? AND revoked_at IS NULL`, hash).
		Scan(&t.ID, &t.Name, &t.Prefix, &t.CreatedBy, &created, &lastUsed, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.CreatedAt = parseStamp(created)
	t.LastUsedAt = parseStampPtr(lastUsed)
	t.RevokedAt = parseStampPtr(revoked)
	return &t, nil
}

// TouchMCPToken records a successful authenticated call without failing the
// request when the best-effort write is lost.
func (s *Store) TouchMCPToken(id int64) error {
	_, err := s.db.Exec(`UPDATE mcp_tokens SET last_used_at = ? WHERE id = ?`, stamp(time.Now()), id)
	return err
}

// RevokeMCPToken disables a credential and reports whether it was active.
func (s *Store) RevokeMCPToken(id int64) (bool, error) {
	res, err := s.db.Exec(`UPDATE mcp_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		stamp(time.Now()), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
