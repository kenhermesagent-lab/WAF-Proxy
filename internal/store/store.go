// Package store persists all gateway state in SQLite.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	_ "modernc.org/sqlite"
)

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// ErrDuplicate is returned when a unique name is already taken.
var ErrDuplicate = errors.New("duplicate")

// ErrAlreadySetup is returned when the initial administrator already exists.
var ErrAlreadySetup = errors.New("setup already completed")

// Open opens (creating if needed) the database inside dir and applies the schema.
func Open(dir string) (*Store, error) {
	path := filepath.Join(dir, "wafproxy.db")
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(time.Hour)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS schema_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  totp_secret TEXT NOT NULL DEFAULT '',
  totp_enabled INTEGER NOT NULL DEFAULT 0,
  recovery_codes TEXT NOT NULL DEFAULT '',
  totp_last_step INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  ua TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  builtin INTEGER NOT NULL DEFAULT 0,
  mode TEXT NOT NULL DEFAULT 'block',
  paranoia INTEGER NOT NULL DEFAULT 1,
  anomaly INTEGER NOT NULL DEFAULT 5,
  allowed_methods TEXT NOT NULL DEFAULT 'GET,HEAD,POST',
  max_body INTEGER NOT NULL DEFAULT 131072,
  exceptions TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS certificates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domains TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT 'manual',
  status TEXT NOT NULL DEFAULT 'pending',
  issued_at TEXT,
  expires_at TEXT,
  cert_pem BLOB,
  key_pem BLOB,
  is_wildcard INTEGER NOT NULL DEFAULT 0,
  renew_mode TEXT NOT NULL DEFAULT 'before_expiry',
  last_error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dns_credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  provider TEXT NOT NULL,
  label TEXT NOT NULL,
  creds_enc TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_providers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL DEFAULT 'generic',
  verify_url TEXT NOT NULL,
  login_url TEXT NOT NULL DEFAULT '',
  header TEXT NOT NULL DEFAULT 'X-Wafproxy-Auth',
  secret TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS proxies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hostname TEXT NOT NULL UNIQUE,
  enabled INTEGER NOT NULL DEFAULT 1,
  cert_id INTEGER REFERENCES certificates(id) ON DELETE SET NULL,
  profile_id INTEGER REFERENCES profiles(id) ON DELETE SET NULL,
  gate_mode TEXT NOT NULL DEFAULT 'off',
  gate_secret TEXT NOT NULL DEFAULT '',
  gate_totp_hint TEXT NOT NULL DEFAULT '',
  fingerprint TEXT NOT NULL DEFAULT 'strict',
  bot_level TEXT NOT NULL DEFAULT 'light',
  maintenance INTEGER NOT NULL DEFAULT 0,
  waf_mode TEXT NOT NULL DEFAULT 'inherit',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS protection_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  builtin INTEGER NOT NULL DEFAULT 0,
  force_https INTEGER NOT NULL DEFAULT 1,
  hsts INTEGER NOT NULL DEFAULT 1,
  hsts_subdomains INTEGER NOT NULL DEFAULT 1,
  frame_options TEXT NOT NULL DEFAULT 'sameorigin',
  nosniff INTEGER NOT NULL DEFAULT 1,
  referrer_policy TEXT NOT NULL DEFAULT 'strict-origin-when-cross-origin',
  csp TEXT NOT NULL DEFAULT '',
  permissions_policy TEXT NOT NULL DEFAULT '',
  hide_server INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS access_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  policy_ids TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS upstreams (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  proxy_id INTEGER NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  weight INTEGER NOT NULL DEFAULT 1,
  enabled INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_upstreams_proxy ON upstreams(proxy_id);
CREATE TABLE IF NOT EXISTS routes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  proxy_id INTEGER NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  match TEXT NOT NULL,
  target TEXT NOT NULL,
  strip_prefix INTEGER NOT NULL DEFAULT 0,
  priority INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_routes_proxy ON routes(proxy_id);
CREATE TABLE IF NOT EXISTS policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scope TEXT NOT NULL DEFAULT 'global',
  proxy_id INTEGER REFERENCES proxies(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  action TEXT NOT NULL DEFAULT 'block',
  priority INTEGER NOT NULL DEFAULT 100,
  enabled INTEGER NOT NULL DEFAULT 1,
  note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_policies_scope ON policies(scope, enabled);
CREATE TABLE IF NOT EXISTS bans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cidr TEXT NOT NULL,
  reason TEXT NOT NULL,
  source TEXT NOT NULL,
  permanent INTEGER NOT NULL DEFAULT 0,
  hits INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  expires_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_bans_cidr ON bans(cidr);
CREATE INDEX IF NOT EXISTS idx_bans_exp ON bans(expires_at);
CREATE TABLE IF NOT EXISTS feeds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  url TEXT NOT NULL,
  action TEXT NOT NULL DEFAULT 'block',
  interval_s INTEGER NOT NULL DEFAULT 900,
  enabled INTEGER NOT NULL DEFAULT 0,
  builtin INTEGER NOT NULL DEFAULT 0,
  local INTEGER NOT NULL DEFAULT 0,
  filename TEXT NOT NULL DEFAULT '',
  local_path TEXT NOT NULL DEFAULT '',
  etag TEXT NOT NULL DEFAULT '',
  last_modified TEXT NOT NULL DEFAULT '',
  last_fetch TEXT,
  last_count INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'pending',
  last_error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  proxy_id INTEGER,
  host TEXT NOT NULL DEFAULT '',
  src_ip TEXT NOT NULL DEFAULT '',
  country TEXT NOT NULL DEFAULT '',
  asn INTEGER NOT NULL DEFAULT 0,
  lat REAL NOT NULL DEFAULT 0,
  lon REAL NOT NULL DEFAULT 0,
  method TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL DEFAULT '',
  status INTEGER NOT NULL DEFAULT 0,
  bytes_in INTEGER NOT NULL DEFAULT 0,
  bytes_out INTEGER NOT NULL DEFAULT 0,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  stage TEXT NOT NULL DEFAULT '',
  rule_id TEXT NOT NULL DEFAULT '',
  rule_msg TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL DEFAULT 'allow',
  ua TEXT NOT NULL DEFAULT '',
  sample INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_proxy ON events(proxy_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_stage ON events(stage, ts);
CREATE TABLE IF NOT EXISTS flows (
  hour TEXT NOT NULL,
  proxy_id INTEGER NOT NULL,
  reqs INTEGER NOT NULL DEFAULT 0,
  bytes_in INTEGER NOT NULL DEFAULT 0,
  bytes_out INTEGER NOT NULL DEFAULT 0,
  blocked INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (hour, proxy_id)
);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  channel TEXT NOT NULL,
  kind TEXT NOT NULL,
  dedupe TEXT NOT NULL DEFAULT '',
  payload TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  sent_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_state ON alerts(state, id);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  user TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
CREATE TABLE IF NOT EXISTS gate_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  totp_secret TEXT NOT NULL DEFAULT '',
  totp_enabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS gate_acl (
  proxy_id INTEGER NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  PRIMARY KEY (proxy_id, username)
);
CREATE TABLE IF NOT EXISTS anomaly_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  proxy_id INTEGER NOT NULL DEFAULT 0,
  proxy_host TEXT NOT NULL DEFAULT '',
  window_start TEXT NOT NULL,
  window_seconds INTEGER NOT NULL DEFAULT 60,
  value REAL NOT NULL DEFAULT 0,
  baseline REAL NOT NULL DEFAULT 0,
  detail TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  acknowledged_by TEXT NOT NULL DEFAULT '',
  acknowledged_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_anomaly_kind ON anomaly_events(kind, proxy_id, state, last_seen);
CREATE TABLE IF NOT EXISTS gate_failures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  proxy_id INTEGER NOT NULL DEFAULT 0,
  username TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  ts TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_gate_failures_ip ON gate_failures(ip, ts);
CREATE TABLE IF NOT EXISTS gate_sessions (
  id TEXT PRIMARY KEY,
  proxy_id INTEGER NOT NULL,
  username TEXT NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  ua TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_gate_sessions_exp ON gate_sessions(expires_at);
CREATE TABLE IF NOT EXISTS username_bans (
  username TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  created_by TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  expires_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_username_bans_exp ON username_bans(expires_at);
CREATE TABLE IF NOT EXISTS mcp_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  prefix TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_mcp_tokens_active ON mcp_tokens(revoked_at);
`

// schemaVersion is bumped whenever migrateAddColumns gains a step, so operators
// can tell which additive migrations a database has seen.
const schemaVersion = "8"

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	if err := s.migrateAddColumns(); err != nil {
		return err
	}
	if err := s.seedProfiles(); err != nil {
		return err
	}
	if err := s.seedProtectionProfiles(); err != nil {
		return err
	}
	return s.seedFeeds()
}

// migrateAddColumns adds columns introduced after the first release. The base
// schema uses CREATE TABLE IF NOT EXISTS, which never alters an existing table,
// so every new column needs an explicit, idempotent step here.
func (s *Store) migrateAddColumns() error {
	steps := []struct{ table, column, ddl string }{
		{"users", "totp_last_step", `ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0`},
		{"certificates", "renew_mode", `ALTER TABLE certificates ADD COLUMN renew_mode TEXT NOT NULL DEFAULT 'before_expiry'`},
		{"gate_failures", "username", `ALTER TABLE gate_failures ADD COLUMN username TEXT NOT NULL DEFAULT ''`},
		{"gate_failures", "reason", `ALTER TABLE gate_failures ADD COLUMN reason TEXT NOT NULL DEFAULT ''`},
		{"feeds", "local", `ALTER TABLE feeds ADD COLUMN local INTEGER NOT NULL DEFAULT 0`},
		{"feeds", "filename", `ALTER TABLE feeds ADD COLUMN filename TEXT NOT NULL DEFAULT ''`},
		{"feeds", "local_path", `ALTER TABLE feeds ADD COLUMN local_path TEXT NOT NULL DEFAULT ''`},
		{"proxies", "protection_profile_id", `ALTER TABLE proxies ADD COLUMN protection_profile_id INTEGER REFERENCES protection_profiles(id) ON DELETE SET NULL`},
		{"proxies", "access_profile_id", `ALTER TABLE proxies ADD COLUMN access_profile_id INTEGER REFERENCES access_profiles(id) ON DELETE SET NULL`},
		{"proxies", "auth_provider_id", `ALTER TABLE proxies ADD COLUMN auth_provider_id INTEGER REFERENCES auth_providers(id) ON DELETE SET NULL`},
	}
	for _, step := range steps {
		has, err := s.hasColumn(step.table, step.column)
		if err != nil {
			return fmt.Errorf("inspect %s.%s: %w", step.table, step.column, err)
		}
		if has {
			continue
		}
		if _, err := s.db.Exec(step.ddl); err != nil {
			return fmt.Errorf("migrate %s.%s: %w", step.table, step.column, err)
		}
	}
	_, err := s.db.Exec(`INSERT INTO schema_meta(key, value) VALUES('version', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, schemaVersion)
	return err
}

func (s *Store) hasColumn(table, column string) (bool, error) {
	rows, err := s.db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// ---------- helpers ----------

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func i2b(i int) bool { return i != 0 }

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func parseStamp(v string) time.Time {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

func parseStampPtr(v sql.NullString) *time.Time {
	if !v.Valid || v.String == "" {
		return nil
	}
	t := parseStamp(v.String)
	return &t
}

func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return stamp(*t)
}

// ---------- settings ----------

// Settings returns all settings.
func (s *Store) Settings() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// GetSetting returns one setting or an empty string.
func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting writes one setting.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// SetSettings writes several settings atomically.
func (s *Store) SetSettings(kv map[string]string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for k, v := range kv {
		if _, err := tx.Exec(`INSERT INTO settings(key, value) VALUES(?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value`, k, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---------- users and sessions ----------

// User is an administrator account.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	TOTPSecret   string
	TOTPEnabled  bool
	Recovery     string
	CreatedAt    time.Time
}

// CountUsers returns the number of administrator accounts.
func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser inserts an administrator.
func (s *Store) CreateUser(username, hash, totpSecret, recovery string, totpEnabled bool) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO users(username, password_hash, totp_secret, totp_enabled, recovery_codes, created_at)
		VALUES(?, ?, ?, ?, ?, ?)`, username, hash, totpSecret, b2i(totpEnabled), recovery, stamp(time.Now()))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// CreateFirstUser inserts the initial administrator only while the users table
// is empty, so two setup requests racing on a fresh instance cannot both claim
// it. The insert is a single statement, so the check and the write cannot be
// separated by a concurrent request.
func (s *Store) CreateFirstUser(username, hash, totpSecret, recovery string, totpEnabled bool) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO users(username, password_hash, totp_secret, totp_enabled, recovery_codes, created_at)
		SELECT ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)`,
		username, hash, totpSecret, b2i(totpEnabled), recovery, stamp(time.Now()))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, ErrAlreadySetup
	}
	return res.LastInsertId()
}

func scanUser(row interface {
	Scan(dest ...any) error
}) (*User, error) {
	var u User
	var created string
	var enabled int
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.TOTPSecret, &enabled, &u.Recovery, &created)
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

// UserByUsername loads an administrator by name.
func (s *Store) UserByUsername(username string) (*User, error) {
	return scanUser(s.db.QueryRow(`SELECT id, username, password_hash, totp_secret, totp_enabled, recovery_codes, created_at
		FROM users WHERE username = ?`, username))
}

// UserByID loads an administrator by ID.
func (s *Store) UserByID(id int64) (*User, error) {
	return scanUser(s.db.QueryRow(`SELECT id, username, password_hash, totp_secret, totp_enabled, recovery_codes, created_at
		FROM users WHERE id = ?`, id))
}

// UpdateUserTOTP replaces the TOTP secret and recovery codes.
func (s *Store) UpdateUserTOTP(id int64, secret, recovery string, enabled bool) error {
	_, err := s.db.Exec(`UPDATE users SET totp_secret = ?, recovery_codes = ?, totp_enabled = ? WHERE id = ?`,
		secret, recovery, b2i(enabled), id)
	return err
}

// UpdateUserPassword replaces the password hash.
func (s *Store) UpdateUserPassword(id int64, hash string) error {
	_, err := s.db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, hash, id)
	return err
}

// Session is an authenticated administrator session.
type Session struct {
	ID        string
	UserID    int64
	Username  string
	CSRF      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CreateSession stores a new session.
func (s *Store) CreateSession(id string, userID int64, csrf, ip, ua string, expires time.Time) error {
	_, err := s.db.Exec(`INSERT INTO sessions(id, user_id, csrf, ip, ua, created_at, expires_at)
		VALUES(?, ?, ?, ?, ?, ?, ?)`, id, userID, csrf, ip, ua, stamp(time.Now()), stamp(expires))
	return err
}

// LookupSession returns a live session with its username.
func (s *Store) LookupSession(id string) (*Session, error) {
	var out Session
	var created, exp string
	err := s.db.QueryRow(`SELECT s.id, s.user_id, u.username, s.csrf, s.created_at, s.expires_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.id = ? AND s.expires_at > ?`, id, stamp(time.Now())).
		Scan(&out.ID, &out.UserID, &out.Username, &out.CSRF, &created, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	out.CreatedAt = parseStamp(created)
	out.ExpiresAt = parseStamp(exp)
	return &out, nil
}

// TouchSession extends a session's idle expiry.
func (s *Store) TouchSession(id string, expires time.Time) error {
	_, err := s.db.Exec(`UPDATE sessions SET expires_at = ? WHERE id = ?`, stamp(expires), id)
	return err
}

// UpdateUserRecovery replaces the stored recovery-code hashes.
func (s *Store) UpdateUserRecovery(id int64, recovery string) error {
	_, err := s.db.Exec(`UPDATE users SET recovery_codes = ? WHERE id = ?`, recovery, id)
	return err
}

// ClaimTOTPStep records the time step of an accepted authenticator code and
// reports whether it was still unused. The UPDATE is conditional, so two
// concurrent logins cannot spend the same code, and a code captured from the
// wire is useless after the legitimate login has used it.
func (s *Store) ClaimTOTPStep(userID, step int64) (bool, error) {
	res, err := s.db.Exec(`UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`,
		step, userID, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// DeleteSession removes one session.
func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// PurgeSessions removes expired sessions and gate sessions.
func (s *Store) PurgeSessions() error {
	now := stamp(time.Now())
	if _, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, now); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM gate_sessions WHERE expires_at <= ?`, now)
	return err
}

// ---------- audit ----------

// AddAudit appends an audit entry.
func (s *Store) AddAudit(user, action, detail, ip string) {
	_, _ = s.db.Exec(`INSERT INTO audit(ts, user, action, detail, ip) VALUES(?, ?, ?, ?, ?)`,
		stamp(time.Now()), user, action, detail, ip)
}

// ListAudit returns recent audit entries.
func (s *Store) ListAudit(limit int) ([]model.AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT id, ts, user, action, detail, ip FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AuditEntry{}
	for rows.Next() {
		var e model.AuditEntry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.User, &e.Action, &e.Detail, &e.IP); err != nil {
			return nil, err
		}
		e.TS = parseStamp(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// trim is used by tests and long-form detail fields.
func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
