// Package store persists all gateway state in SQLite.
package store

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/rbac"
	_ "modernc.org/sqlite"
)

// Store wraps the SQLite database. A store opened by Open is scoped to the
// default site; InSite returns a copy scoped to another site, and Unscoped
// returns one that reads every site for migrations and the process engines.
type Store struct {
	db *sql.DB
	// site owns the rows this handle reads and writes. 0 means every site.
	site int64
	// defaultSite owns the rows that name no site of their own.
	defaultSite int64
	// sessionKey hides session cookies in the database, so a copy of the file
	// does not hand out live admin sessions.
	sessionKey []byte
	// box seals secret columns at rest. A nil box reads plaintext rows only,
	// which is what the CLI paths that never serve a request need.
	box *wfcrypto.Box
	// auditMu serialises audit appends so each row links to the one before it.
	// A pointer, so a site-scoped copy shares the same lock.
	auditMu *sync.Mutex
	// capture holds the HA toggles. It is shared by every site-scoped copy, so
	// a promotion reaches handles that were made before it.
	capture *haCapture
}

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// ErrHostWideSetting refuses to move a process-wide key into one site.
var ErrHostWideSetting = errors.New("host-wide setting cannot be set per site")

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
	// SQLite writes serialise, but reads scale with the connection pool. The
	// default tracks the host's CPUs so a 8 vCPU edge does not queue every
	// analytics query behind the four connections a small VM needs. An operator
	// can pin it with WAFPROXY_DB_CONNS.
	conns := runtime.NumCPU() * 2
	if conns < 4 {
		conns = 4
	}
	if conns > 32 {
		conns = 32
	}
	if raw := os.Getenv("WAFPROXY_DB_CONNS"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 && n <= 64 {
			conns = n
		}
	}
	db.SetMaxOpenConns(conns)
	db.SetMaxIdleConns(conns)
	db.SetConnMaxLifetime(time.Hour)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	s := &Store{db: db, auditMu: &sync.Mutex{}, capture: &haCapture{}}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

// InSite returns a handle that reads and writes only the given site's rows.
func (s *Store) InSite(id int64) *Store {
	copy := *s
	copy.site = id
	return &copy
}

// Unscoped returns a handle that reads every site. Engines that serve all
// hostnames (TLS selection, the proxy, the ban kernel) need one.
func (s *Store) Unscoped() *Store {
	copy := *s
	copy.site = 0
	return &copy
}

// SiteID reports which site this handle is scoped to; 0 means every site.
func (s *Store) SiteID() int64 { return s.site }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// SetSessionKey installs the key that session identifiers are derived from. It
// must be set before the store serves requests, and must stay stable across
// restarts or every session is invalidated.
func (s *Store) SetSessionKey(key []byte) { s.sessionKey = key }

// QuickCheck runs PRAGMA quick_check, the cheap integrity check a promotion
// preflight uses. An ok database returns "ok".
func (s *Store) QuickCheck() (string, error) {
	var v string
	err := s.db.QueryRow(`PRAGMA quick_check(1)`).Scan(&v)
	return v, err
}

// Writable proves the database accepts a write and rolls it back, so a
// promotion does not discover a read-only volume after traffic has moved.
func (s *Store) Writable() (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS ha_write_probe(x INTEGER)`,
		`INSERT INTO ha_write_probe VALUES(1)`,
		`DROP TABLE ha_write_probe`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return false, err
		}
	}
	return true, nil
}

// SetAuditEnabled turns local audit writes on or off. A standby turns them off:
// its audit rows arrive from the active, and a local row would break the hash
// chain VerifyAuditChain walks after a failover.
func (s *Store) SetAuditEnabled(enabled bool) {
	if s.capture != nil {
		s.capture.auditOff.Store(!enabled)
	}
}

// SetSecretBox installs the box that seals secret columns. It must be set
// before certificates are read or written, and stay stable across restarts.
func (s *Store) SetSecretBox(box *wfcrypto.Box) { s.box = box }

// sealedPrefix marks a column this build encrypted. A value without it is a
// plaintext row from an older release and is read as-is.
const sealedPrefix = "enc:v1:"

func (s *Store) sealSecret(v []byte) ([]byte, error) {
	if len(v) == 0 || s.box == nil || bytes.HasPrefix(v, []byte(sealedPrefix)) {
		return v, nil
	}
	out, err := s.box.Seal(string(v))
	if err != nil {
		return nil, err
	}
	return []byte(sealedPrefix + out), nil
}

func (s *Store) openSecret(v []byte) ([]byte, error) {
	if len(v) == 0 || !bytes.HasPrefix(v, []byte(sealedPrefix)) {
		return v, nil
	}
	if s.box == nil {
		return nil, errors.New("store: secret is sealed but no master key is loaded")
	}
	out, err := s.box.Open(string(v[len(sealedPrefix):]))
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

// sessionID is what the sessions table stores: a keyed digest of the cookie
// value. The cookie itself is never written down, so reading the database file
// is not enough to replay a session.
func (s *Store) sessionID(token string) string {
	return keyedID(s.sessionKey, "wafproxy-session\x00", token)
}

// gateID is the same idea for visitor sessions, with its own separator so an
// admin cookie and a gate cookie can never produce the same row key.
func (s *Store) gateID(token string) string { return keyedID(s.sessionKey, "wafproxy-gate\x00", token) }

func keyedID(key []byte, domain, token string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(domain))
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

const schema = `
CREATE TABLE IF NOT EXISTS schema_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  console_host TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sites_console ON sites(console_host) WHERE console_host <> '';
CREATE TABLE IF NOT EXISTS site_settings (
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  PRIMARY KEY (site_id, key)
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  totp_secret TEXT NOT NULL DEFAULT '',
  totp_enabled INTEGER NOT NULL DEFAULT 0,
  recovery_codes TEXT NOT NULL DEFAULT '',
  totp_last_step INTEGER NOT NULL DEFAULT 0,
  role_id INTEGER NOT NULL DEFAULT 0,
  auth_source TEXT NOT NULL DEFAULT 'local',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  builtin INTEGER NOT NULL DEFAULT 0,
  permissions TEXT NOT NULL DEFAULT ''
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
CREATE TABLE IF NOT EXISTS trusted_devices (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  site_id INTEGER NOT NULL DEFAULT 0,
  ua TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_trusted_devices_user ON trusted_devices(user_id);
CREATE TABLE IF NOT EXISTS password_resets (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  site_id INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS invites (
  token_hash TEXT PRIMARY KEY,
  site_id INTEGER NOT NULL DEFAULT 0,
  email TEXT NOT NULL,
  first_name TEXT NOT NULL DEFAULT '',
  last_name TEXT NOT NULL DEFAULT '',
  role_id INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_invites_email ON invites(email);
CREATE TABLE IF NOT EXISTS profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  builtin INTEGER NOT NULL DEFAULT 0,
  mode TEXT NOT NULL DEFAULT 'block',
  paranoia INTEGER NOT NULL DEFAULT 1,
  anomaly INTEGER NOT NULL DEFAULT 5,
  allowed_methods TEXT NOT NULL DEFAULT 'GET,HEAD,POST',
  max_body INTEGER NOT NULL DEFAULT 67108864,
  exceptions TEXT NOT NULL DEFAULT '',
  responses TEXT NOT NULL DEFAULT 'off',
  max_response INTEGER NOT NULL DEFAULT 0,
  login_paths TEXT NOT NULL DEFAULT '',
  login_rps INTEGER NOT NULL DEFAULT 0,
  login_burst INTEGER NOT NULL DEFAULT 0,
  admin_paths TEXT NOT NULL DEFAULT '',
  admin_ips TEXT NOT NULL DEFAULT '',
  bundle_modes TEXT NOT NULL DEFAULT '{}'
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
  challenge TEXT NOT NULL DEFAULT 'dns-01',
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
CREATE TABLE IF NOT EXISTS console_auth (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0,
  host TEXT NOT NULL DEFAULT '',
  port INTEGER NOT NULL DEFAULT 0,
  secret TEXT NOT NULL DEFAULT '',
  base_dn TEXT NOT NULL DEFAULT '',
  bind_dn TEXT NOT NULL DEFAULT '',
  bind_password TEXT NOT NULL DEFAULT '',
  user_filter TEXT NOT NULL DEFAULT '',
  group_filter TEXT NOT NULL DEFAULT '',
  email_attr TEXT NOT NULL DEFAULT 'mail',
  use_tls INTEGER NOT NULL DEFAULT 0,
  start_tls INTEGER NOT NULL DEFAULT 0,
  skip_verify INTEGER NOT NULL DEFAULT 0,
  timeout_seconds INTEGER NOT NULL DEFAULT 8,
  default_role_id INTEGER NOT NULL DEFAULT 0,
  role_map TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  site_id INTEGER NOT NULL DEFAULT 0,
  UNIQUE(site_id, kind)
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
  max_body INTEGER NOT NULL DEFAULT 0,
  body_skip TEXT NOT NULL DEFAULT '[]',
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
CREATE TABLE IF NOT EXISTS access_lists (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  name TEXT NOT NULL UNIQUE,
  ips TEXT NOT NULL DEFAULT '',
  countries TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT ''
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
  city TEXT NOT NULL DEFAULT '',
  asn INTEGER NOT NULL DEFAULT 0,
  lat REAL NOT NULL DEFAULT 0,
  lon REAL NOT NULL DEFAULT 0,
  method TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL DEFAULT '',
  query TEXT NOT NULL DEFAULT '',
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
CREATE TABLE IF NOT EXISTS utilization (
  hour TEXT PRIMARY KEY,
  cpu REAL NOT NULL DEFAULT 0,
  mem_used INTEGER NOT NULL DEFAULT 0,
  mem_total INTEGER NOT NULL DEFAULT 0,
  wan_rx REAL NOT NULL DEFAULT 0,
  wan_tx REAL NOT NULL DEFAULT 0,
  proxy_rx REAL NOT NULL DEFAULT 0,
  proxy_tx REAL NOT NULL DEFAULT 0,
  reqs INTEGER NOT NULL DEFAULT 0,
  blocked INTEGER NOT NULL DEFAULT 0,
  samples INTEGER NOT NULL DEFAULT 1
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
  ip TEXT NOT NULL DEFAULT '',
  hash TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
CREATE TABLE IF NOT EXISTS audit_snapshots (
  audit_id INTEGER PRIMARY KEY,
  entity TEXT NOT NULL,
  entity_id INTEGER NOT NULL,
  before TEXT NOT NULL DEFAULT '',
  after TEXT NOT NULL DEFAULT ''
);
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
CREATE TABLE IF NOT EXISTS agent_deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  link_id INTEGER NOT NULL,
  event_id INTEGER NOT NULL DEFAULT 0,
  kind TEXT NOT NULL,
  body TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  last_status INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  delivered_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_agent_deliveries_due ON agent_deliveries(state, next_attempt_at);
CREATE TABLE IF NOT EXISTS agent_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  endpoint TEXT NOT NULL,
  secret TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
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
CREATE TABLE IF NOT EXISTS log_views (
  name TEXT PRIMARY KEY,
  query TEXT NOT NULL,
  updated_by TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_prefs (
  user_id INTEGER NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (user_id, key)
);
CREATE TABLE IF NOT EXISTS ha_outbox (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  origin TEXT NOT NULL,
  origin_seq INTEGER NOT NULL DEFAULT 0,
  kind TEXT NOT NULL,
  op TEXT NOT NULL,
  row_id TEXT NOT NULL DEFAULT '',
  payload BLOB NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ha_outbox_created ON ha_outbox(created_at);
CREATE TABLE IF NOT EXISTS ha_peer_ack (
  peer TEXT PRIMARY KEY,
  acked_seq INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ha_applied (
  origin TEXT NOT NULL,
  origin_seq INTEGER NOT NULL,
  applied_at TEXT NOT NULL,
  PRIMARY KEY (origin, origin_seq)
);
`

// schemaVersion is bumped whenever migrateAddColumns gains a step, so operators
// can tell which additive migrations a database has seen.
const schemaVersion = "27"

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	if err := s.migrateAddColumns(); err != nil {
		return err
	}
	if err := s.seedRoles(); err != nil {
		return err
	}
	if err := s.seedProfiles(); err != nil {
		return err
	}
	if err := s.seedProtectionProfiles(); err != nil {
		return err
	}
	if err := s.seedFeeds(); err != nil {
		return err
	}
	return s.migrateSites()
}

// migrateAddColumns adds columns introduced after the first release. The base
// schema uses CREATE TABLE IF NOT EXISTS, which never alters an existing table,
// so every new column needs an explicit, idempotent step here.
func (s *Store) migrateAddColumns() error {
	steps := []struct{ table, column, ddl string }{
		{"events", "city", `ALTER TABLE events ADD COLUMN city TEXT NOT NULL DEFAULT ''`},
		{"events", "query", `ALTER TABLE events ADD COLUMN query TEXT NOT NULL DEFAULT ''`},
		{"users", "totp_last_step", `ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0`},
		{"users", "role_id", `ALTER TABLE users ADD COLUMN role_id INTEGER NOT NULL DEFAULT 0`},
		{"users", "auth_source", `ALTER TABLE users ADD COLUMN auth_source TEXT NOT NULL DEFAULT 'local'`},
		// Password-reset mail goes to the administrator's own address.
		{"users", "email", `ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''`},
		// A remembered browser lists its user agent and address, so Account can
		// show which device each row is before revoking it.
		{"trusted_devices", "ua", `ALTER TABLE trusted_devices ADD COLUMN ua TEXT NOT NULL DEFAULT ''`},
		{"trusted_devices", "ip", `ALTER TABLE trusted_devices ADD COLUMN ip TEXT NOT NULL DEFAULT ''`},
		{"certificates", "renew_mode", `ALTER TABLE certificates ADD COLUMN renew_mode TEXT NOT NULL DEFAULT 'before_expiry'`},
		{"certificates", "challenge", `ALTER TABLE certificates ADD COLUMN challenge TEXT NOT NULL DEFAULT 'dns-01'`},
		{"gate_failures", "username", `ALTER TABLE gate_failures ADD COLUMN username TEXT NOT NULL DEFAULT ''`},
		{"gate_failures", "reason", `ALTER TABLE gate_failures ADD COLUMN reason TEXT NOT NULL DEFAULT ''`},
		{"feeds", "local", `ALTER TABLE feeds ADD COLUMN local INTEGER NOT NULL DEFAULT 0`},
		{"feeds", "filename", `ALTER TABLE feeds ADD COLUMN filename TEXT NOT NULL DEFAULT ''`},
		{"feeds", "local_path", `ALTER TABLE feeds ADD COLUMN local_path TEXT NOT NULL DEFAULT ''`},
		{"proxies", "protection_profile_id", `ALTER TABLE proxies ADD COLUMN protection_profile_id INTEGER REFERENCES protection_profiles(id) ON DELETE SET NULL`},
		{"proxies", "access_profile_id", `ALTER TABLE proxies ADD COLUMN access_profile_id INTEGER REFERENCES access_profiles(id) ON DELETE SET NULL`},
		{"proxies", "auth_provider_id", `ALTER TABLE proxies ADD COLUMN auth_provider_id INTEGER REFERENCES auth_providers(id) ON DELETE SET NULL`},
		// An access profile now carries the roles of its lists and the two
		// protection profiles a host needs, so a proxy selects one profile.
		{"access_profiles", "rule_roles", `ALTER TABLE access_profiles ADD COLUMN rule_roles TEXT NOT NULL DEFAULT ''`},
		{"access_profiles", "waf_profile_id", `ALTER TABLE access_profiles ADD COLUMN waf_profile_id INTEGER REFERENCES profiles(id) ON DELETE SET NULL`},
		{"access_profiles", "protection_profile_id", `ALTER TABLE access_profiles ADD COLUMN protection_profile_id INTEGER REFERENCES protection_profiles(id) ON DELETE SET NULL`},
		// Named blocklist/whitelist bundles a profile attaches as a whole.
		{"access_profiles", "list_ids", `ALTER TABLE access_profiles ADD COLUMN list_ids TEXT NOT NULL DEFAULT ''`},
		// A rolled-up permanent-ban list is enforced even for allowlisted
		// addresses, matching the ban it replaced.
		{"feeds", "always_block", `ALTER TABLE feeds ADD COLUMN always_block INTEGER NOT NULL DEFAULT 0`},
		// The response ceiling and the two path-scoped limits live on the WAF
		// profile, which is what a proxy already selects.
		{"profiles", "max_response", `ALTER TABLE profiles ADD COLUMN max_response INTEGER NOT NULL DEFAULT 0`},
		// Response inspection is opt-in per profile: off, flag or block.
		{"profiles", "responses", `ALTER TABLE profiles ADD COLUMN responses TEXT NOT NULL DEFAULT 'off'`},
		{"profiles", "login_paths", `ALTER TABLE profiles ADD COLUMN login_paths TEXT NOT NULL DEFAULT ''`},
		{"profiles", "login_rps", `ALTER TABLE profiles ADD COLUMN login_rps INTEGER NOT NULL DEFAULT 0`},
		{"profiles", "login_burst", `ALTER TABLE profiles ADD COLUMN login_burst INTEGER NOT NULL DEFAULT 0`},
		{"profiles", "admin_paths", `ALTER TABLE profiles ADD COLUMN admin_paths TEXT NOT NULL DEFAULT ''`},
		{"profiles", "admin_ips", `ALTER TABLE profiles ADD COLUMN admin_ips TEXT NOT NULL DEFAULT ''`},
		// Per-profile mode for each installed signature bundle: off, log or
		// block. An empty object means every bundle logs only.
		{"profiles", "bundle_modes", `ALTER TABLE profiles ADD COLUMN bundle_modes TEXT NOT NULL DEFAULT '{}'`},
		// Audit rows chain by hash so an edited row is detectable.
		{"audit", "hash", `ALTER TABLE audit ADD COLUMN hash TEXT NOT NULL DEFAULT ''`},
		// Agent tokens can be limited to read, ban or session tools.
		{"mcp_tokens", "scopes", `ALTER TABLE mcp_tokens ADD COLUMN scopes TEXT NOT NULL DEFAULT ''`},
		// Balancing, health probes and per-site capacity are configured per
		// site; zero or empty values mean the defaults.
		{"proxies", "lb_policy", `ALTER TABLE proxies ADD COLUMN lb_policy TEXT NOT NULL DEFAULT 'weighted_rr'`},
		{"proxies", "health_path", `ALTER TABLE proxies ADD COLUMN health_path TEXT NOT NULL DEFAULT '/'`},
		{"proxies", "health_expect", `ALTER TABLE proxies ADD COLUMN health_expect TEXT NOT NULL DEFAULT '200-399'`},
		{"proxies", "health_interval", `ALTER TABLE proxies ADD COLUMN health_interval INTEGER NOT NULL DEFAULT 0`},
		{"proxies", "health_fail_after", `ALTER TABLE proxies ADD COLUMN health_fail_after INTEGER NOT NULL DEFAULT 0`},
		{"proxies", "max_inflight", `ALTER TABLE proxies ADD COLUMN max_inflight INTEGER NOT NULL DEFAULT 0`},
		{"proxies", "max_inflight_per_client", `ALTER TABLE proxies ADD COLUMN max_inflight_per_client INTEGER NOT NULL DEFAULT 0`},
		{"upstreams", "max_conns", `ALTER TABLE upstreams ADD COLUMN max_conns INTEGER NOT NULL DEFAULT 0`},
		// Timeout, retries and header rewrites are per site. Header rules are a
		// JSON array so their order is preserved.
		{"proxies", "upstream_timeout", `ALTER TABLE proxies ADD COLUMN upstream_timeout INTEGER NOT NULL DEFAULT 0`},
		{"proxies", "retries", `ALTER TABLE proxies ADD COLUMN retries INTEGER NOT NULL DEFAULT 0`},
		{"proxies", "request_headers", `ALTER TABLE proxies ADD COLUMN request_headers TEXT NOT NULL DEFAULT '[]'`},
		{"proxies", "response_headers", `ALTER TABLE proxies ADD COLUMN response_headers TEXT NOT NULL DEFAULT '[]'`},
		// Routes can match more than a path and carry their own timeout,
		// redirect status and upstream override.
		{"routes", "method", `ALTER TABLE routes ADD COLUMN method TEXT NOT NULL DEFAULT ''`},
		{"routes", "header", `ALTER TABLE routes ADD COLUMN header TEXT NOT NULL DEFAULT ''`},
		{"routes", "query", `ALTER TABLE routes ADD COLUMN query TEXT NOT NULL DEFAULT ''`},
		{"routes", "regex", `ALTER TABLE routes ADD COLUMN regex INTEGER NOT NULL DEFAULT 0`},
		{"routes", "upstream", `ALTER TABLE routes ADD COLUMN upstream TEXT NOT NULL DEFAULT ''`},
		{"routes", "timeout", `ALTER TABLE routes ADD COLUMN timeout INTEGER NOT NULL DEFAULT 0`},
		{"routes", "status", `ALTER TABLE routes ADD COLUMN status INTEGER NOT NULL DEFAULT 0`},
		// Certificates record where they came from: acme, uploaded or internal.
		{"certificates", "source", `ALTER TABLE certificates ADD COLUMN source TEXT NOT NULL DEFAULT 'acme'`},
		// Per-site minimum TLS version; empty means 1.2.
		{"proxies", "tls_min_version", `ALTER TABLE proxies ADD COLUMN tls_min_version TEXT NOT NULL DEFAULT ''`},
		// A site may accept larger buffered bodies than the host default, and may
		// stream selected upload paths without buffering or inspecting them.
		{"proxies", "max_body", `ALTER TABLE proxies ADD COLUMN max_body INTEGER NOT NULL DEFAULT 0`},
		{"proxies", "body_skip", `ALTER TABLE proxies ADD COLUMN body_skip TEXT NOT NULL DEFAULT '[]'`},
		// Every configurable row belongs to a site. migrateSites runs after
		// this pass and hands the rows written before sites existed to the
		// default site, so 0 only survives for the shared builtin profiles.
		{"users", "site_id", `ALTER TABLE users ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"sessions", "site_id", `ALTER TABLE sessions ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"profiles", "site_id", `ALTER TABLE profiles ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"certificates", "site_id", `ALTER TABLE certificates ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"dns_credentials", "site_id", `ALTER TABLE dns_credentials ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"auth_providers", "site_id", `ALTER TABLE auth_providers ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"proxies", "site_id", `ALTER TABLE proxies ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"protection_profiles", "site_id", `ALTER TABLE protection_profiles ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"access_profiles", "site_id", `ALTER TABLE access_profiles ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"access_lists", "site_id", `ALTER TABLE access_lists ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"policies", "site_id", `ALTER TABLE policies ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"bans", "site_id", `ALTER TABLE bans ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"feeds", "site_id", `ALTER TABLE feeds ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"alerts", "site_id", `ALTER TABLE alerts ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"audit", "site_id", `ALTER TABLE audit ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"gate_users", "site_id", `ALTER TABLE gate_users ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"agent_deliveries", "site_id", `ALTER TABLE agent_deliveries ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"agent_links", "site_id", `ALTER TABLE agent_links ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"anomaly_events", "site_id", `ALTER TABLE anomaly_events ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"gate_failures", "site_id", `ALTER TABLE gate_failures ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"gate_sessions", "site_id", `ALTER TABLE gate_sessions ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"username_bans", "site_id", `ALTER TABLE username_bans ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"mcp_tokens", "site_id", `ALTER TABLE mcp_tokens ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
		{"log_views", "site_id", `ALTER TABLE log_views ADD COLUMN site_id INTEGER NOT NULL DEFAULT 0`},
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
	if err := s.dropLegacySessions(); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT INTO schema_meta(key, value) VALUES('version', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, schemaVersion)
	return err
}

// dropLegacySessions clears sessions written before schema 13, when the cookie
// value was the primary key. Those rows cannot be turned into digests (the
// token is not stored anywhere else), and keeping them would leave rows that
// never match a cookie. Everyone signs in once after the upgrade. Gate rows
// are cleared once, at schema 24, when their id became a digest too.
func (s *Store) dropLegacySessions() error {
	var v string
	err := s.db.QueryRow(`SELECT value FROM schema_meta WHERE key = 'version'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) || v == schemaVersion {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	// Only the migrations that changed how a cookie is keyed need this reset.
	// A later additive step must not sign everyone out on upgrade.
	before, convErr := strconv.Atoi(v)
	if convErr == nil && before >= 24 {
		return nil
	}
	if _, err := s.db.Exec(`DELETE FROM sessions`); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM gate_sessions`); err != nil {
		return err
	}
	return nil
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

// Settings returns all settings a site sees: the host table with the site's
// overrides on top.
func (s *Store) Settings() (map[string]string, error) {
	if s.site != 0 {
		return s.SettingsFor(s.site)
	}
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
	if s.site != 0 {
		kv, err := s.SettingsFor(s.site)
		return kv[key], err
	}
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting writes one setting.
func (s *Store) SetSetting(key, value string) error {
	if hostSettingKeys[key] {
		if s.site != 0 && s.site != s.defaultSite {
			return ErrHostWideSetting
		}
		return s.setHostSettings(map[string]string{key: value})
	}
	if s.site != 0 {
		return s.SetSettingsFor(s.site, map[string]string{key: value})
	}
	return s.setHostSettings(map[string]string{key: value})
}

// setHostSettings writes process-wide keys. They live in the host table, so a
// site reads them and never changes them.
func (s *Store) setHostSettings(kv map[string]string) error {
	if len(kv) == 0 {
		return nil
	}
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

// SetSettings writes several settings atomically. A site may set its own
// keys only; host-wide keys in the same map go to the host table as before.
func (s *Store) SetSettings(kv map[string]string) error {
	if s.site == 0 {
		return s.setHostSettings(kv)
	}
	host := map[string]string{}
	for k, v := range kv {
		if hostSettingKeys[k] {
			if s.site != s.defaultSite {
				return ErrHostWideSetting
			}
			host[k] = v
		}
	}
	if err := s.setHostSettings(host); err != nil {
		return err
	}
	return s.SetSettingsFor(s.site, kv)
}

// ---------- users and sessions ----------

// User is an administrator account.
type User struct {
	ID           int64
	Username     string
	Email        string
	PasswordHash string
	TOTPSecret   string
	TOTPEnabled  bool
	Recovery     string
	RoleID       int64
	AuthSource   string
	CreatedAt    time.Time
}

// CountUsers returns the number of administrator accounts.
func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE (? = 0 OR site_id = ?)`, s.site, s.site).Scan(&n)
	return n, err
}

// CreateUser inserts an administrator.
func (s *Store) CreateUser(username, hash, totpSecret, recovery string, totpEnabled bool) (int64, error) {
	return s.CreateUserWithRole(username, hash, totpSecret, recovery, totpEnabled, s.AdminRoleID())
}

// CreateUserWithRole inserts an administrator with an explicit role.
func (s *Store) CreateUserWithRole(username, hash, totpSecret, recovery string, totpEnabled bool, roleID int64) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO users(username, password_hash, totp_secret, totp_enabled, recovery_codes, role_id, created_at, site_id)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, username, hash, totpSecret, b2i(totpEnabled), recovery, roleID, stamp(time.Now()), s.site)
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
	res, err := s.db.Exec(`INSERT INTO users(username, password_hash, totp_secret, totp_enabled, recovery_codes, role_id, created_at, site_id)
		SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM users WHERE (? = 0 OR site_id = ?))`,
		username, hash, totpSecret, b2i(totpEnabled), recovery, s.AdminRoleID(), stamp(time.Now()), s.site, s.site, s.site)
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
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.TOTPSecret, &enabled, &u.Recovery, &u.RoleID, &u.AuthSource, &created)
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
	return scanUser(s.db.QueryRow(`SELECT id, username, email, password_hash, totp_secret, totp_enabled, recovery_codes, role_id, auth_source, created_at
		FROM users WHERE username = ? AND (? = 0 OR site_id = ?)`, username, s.site, s.site))
}

// UserByID loads an administrator by ID.
func (s *Store) UserByID(id int64) (*User, error) {
	return scanUser(s.db.QueryRow(`SELECT id, username, email, password_hash, totp_secret, totp_enabled, recovery_codes, role_id, auth_source, created_at
		FROM users WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site))
}

// UpdateUserTOTP replaces the TOTP secret and recovery codes.
func (s *Store) UpdateUserTOTP(id int64, secret, recovery string, enabled bool) error {
	_, err := s.db.Exec(`UPDATE users SET totp_secret = ?, recovery_codes = ?, totp_enabled = ? WHERE id = ? AND (? = 0 OR site_id = ?)`,
		secret, recovery, b2i(enabled), id, s.site, s.site)
	return err
}

// SetUserEmail stores the address password-reset mail is sent to. An empty
// address is allowed; the reset link is simply not offered for that account.
func (s *Store) SetUserEmail(id int64, email string) error {
	_, err := s.db.Exec(`UPDATE users SET email = ? WHERE id = ? AND (? = 0 OR site_id = ?)`,
		strings.TrimSpace(email), id, s.site, s.site)
	return err
}

// UpdateUserPassword replaces the password hash.
func (s *Store) UpdateUserPassword(id int64, hash string) error {
	_, err := s.db.Exec(`UPDATE users SET password_hash = ? WHERE id = ? AND (? = 0 OR site_id = ?)`, hash, id, s.site, s.site)
	return err
}

// Session is an authenticated administrator session.
type Session struct {
	ID          string
	UserID      int64
	Username    string
	CSRF        string
	Role        string
	Permissions []string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// Can reports whether the session holds a permission.
func (s *Session) Can(permission string) bool { return rbac.Allows(s.Permissions, permission) }

// CreateSession stores a new session. The cookie value is hashed on the way in;
// only the caller ever holds the token itself. The row and its replica entry
// commit together, so the session a client was handed exists on the peer too.
func (s *Store) CreateSession(id string, userID int64, csrf, ip, ua string, expires time.Time) error {
	key := s.sessionID(id)
	return s.upsertChanged("sessions", []string{"id"}, func(db execer) ([]any, error) {
		_, err := db.Exec(`INSERT INTO sessions(id, user_id, csrf, ip, ua, created_at, expires_at, site_id)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, key, userID, csrf, ip, ua, stamp(time.Now()), stamp(expires), s.site)
		return []any{key}, err
	})
}

// LookupSession returns a live session with its username.
func (s *Store) LookupSession(id string) (*Session, error) {
	var out Session
	var created, exp string
	var perms string
	err := s.db.QueryRow(`SELECT s.user_id, u.username, s.csrf, s.created_at, s.expires_at,
		COALESCE(r.name, ''), COALESCE(r.permissions, '')
		FROM sessions s JOIN users u ON u.id = s.user_id
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE s.id = ? AND s.expires_at > ? AND (? = 0 OR s.site_id = ?)`, s.sessionID(id), stamp(time.Now()), s.site, s.site).
		Scan(&out.UserID, &out.Username, &out.CSRF, &created, &exp, &out.Role, &perms)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	out.Permissions = rbac.Parse(perms)
	// Callers keep using the token they hold; the digest never leaves the store.
	out.ID = id
	out.CreatedAt = parseStamp(created)
	out.ExpiresAt = parseStamp(exp)
	return &out, nil
}

// TouchSession extends a session's idle expiry.
func (s *Store) TouchSession(id string, expires time.Time) error {
	_, err := s.db.Exec(`UPDATE sessions SET expires_at = ? WHERE id = ? AND (? = 0 OR site_id = ?)`, stamp(expires), s.sessionID(id), s.site, s.site)
	return err
}

// UpdateUserRecovery replaces the stored recovery-code hashes.
func (s *Store) UpdateUserRecovery(id int64, recovery string) error {
	_, err := s.db.Exec(`UPDATE users SET recovery_codes = ? WHERE id = ? AND (? = 0 OR site_id = ?)`, recovery, id, s.site, s.site)
	return err
}

// ClaimTOTPStep records the time step of an accepted authenticator code and
// reports whether it was still unused. The UPDATE is conditional, so two
// concurrent logins cannot spend the same code, and a code captured from the
// wire is useless after the legitimate login has used it. The claimed step is
// replicated: a code spent on the active must stay spent after a failover.
func (s *Store) ClaimTOTPStep(userID, step int64) (bool, error) {
	if !s.Capturing() {
		res, err := s.db.Exec(`UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ? AND (? = 0 OR site_id = ?)`,
			step, userID, step, s.site, s.site)
		if err != nil {
			return false, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return false, err
		}
		return n == 1, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ? AND (? = 0 OR site_id = ?)`,
		step, userID, step, s.site, s.site)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 1 {
		// Only the replay guard crosses the link, never the password hash or the
		// authenticator secret; configuration travels as a whole snapshot.
		dump := rowDump{
			Columns: []string{"id", "totp_last_step"},
			Row:     []Value{{Kind: "int", Int: userID}, {Kind: "int", Int: step}},
			Key:     []string{"id"},
		}
		if err := s.enqueue(tx, "users", "upsert", dump); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n == 1, nil
}

// DeleteSession removes one session.
func (s *Store) DeleteSession(id string) error {
	_, err := s.deleteCaptured("sessions", []string{"id"}, `id = ? AND (? = 0 OR site_id = ?)`, s.sessionID(id), s.site, s.site)
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

// auditHeadKey stores the newest hash, so deleting trailing rows is detectable.
const auditHeadKey = "audit_head"

// AddAudit appends an audit entry linked by hash to the one before it, so an
// edited or deleted row breaks the chain VerifyAuditChain walks.
func (s *Store) AddAudit(user, action, detail, ip string) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	s.addAuditLocked(user, action, detail, ip)
}

// addAuditLocked appends one entry to the chain and returns its id. The caller
// holds auditMu.
func (s *Store) addAuditLocked(user, action, detail, ip string) int64 {
	if s.capture != nil && s.capture.auditOff.Load() {
		return 0
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0
	}
	defer func() { _ = tx.Rollback() }()
	var prev string
	_ = tx.QueryRow(`SELECT hash FROM audit ORDER BY id DESC LIMIT 1`).Scan(&prev)
	ts := stamp(time.Now())
	hash := auditHash(prev, ts, user, action, detail, ip)
	res, err := tx.Exec(`INSERT INTO audit(ts, user, action, detail, ip, hash, site_id) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		ts, user, action, detail, ip, hash, s.site)
	if err != nil {
		return 0
	}
	if _, err := tx.Exec(`INSERT INTO settings(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, auditHeadKey, hash); err != nil {
		return 0
	}
	id, _ := res.LastInsertId()
	if id > 0 {
		if err := s.captureRow(tx, "audit", []string{"id"}, []any{id}); err != nil {
			return 0
		}
	}
	if err := tx.Commit(); err != nil {
		return 0
	}
	return id
}

// AddAuditSnapshot records a mutation together with the entity state around it,
// so a later reader can show the difference or undo the change. It is
// best-effort: a snapshot failure must never undo or block the change itself.
func (s *Store) AddAuditSnapshot(user, action, detail, ip string, snap model.AuditSnapshot) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	id := s.addAuditLocked(user, action, detail, ip)
	if id == 0 {
		return
	}
	_, _ = s.db.Exec(`INSERT OR REPLACE INTO audit_snapshots(audit_id, entity, entity_id, before, after)
		VALUES(?, ?, ?, ?, ?)`, id, snap.Entity, snap.EntityID, snap.Before, snap.After)
}

// GetAuditSnapshot returns the stored state for one audit entry.
func (s *Store) GetAuditSnapshot(auditID int64) (*model.AuditSnapshot, error) {
	var snap model.AuditSnapshot
	err := s.db.QueryRow(`SELECT s.audit_id, s.entity, s.entity_id, s.before, s.after
		FROM audit_snapshots s JOIN audit a ON a.id = s.audit_id
		WHERE s.audit_id = ? AND (? = 0 OR a.site_id = ?)`, auditID, s.site, s.site).
		Scan(&snap.AuditID, &snap.Entity, &snap.EntityID, &snap.Before, &snap.After)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &snap, nil
}

// GetAuditEntry returns one audit entry by id.
func (s *Store) GetAuditEntry(id int64) (*model.AuditEntry, error) {
	var e model.AuditEntry
	var ts string
	err := s.db.QueryRow(`SELECT id, ts, user, action, detail, ip FROM audit
		WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site).
		Scan(&e.ID, &ts, &e.User, &e.Action, &e.Detail, &e.IP)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	e.TS = parseStamp(ts)
	return &e, nil
}

func auditHash(prev, ts, user, action, detail, ip string) string {
	h := sha256.New()
	for _, part := range []string{prev, ts, user, action, detail, ip} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyAuditChain recomputes every hash and returns the first problem it finds
// ("" when the chain is intact). Rows written before the chain existed have no
// hash and are skipped; a later empty hash counts as tampering. The stored head
// catches rows removed from the end. An unkeyed chain catches edits to the
// database, not an attacker who can rewrite every row and the head.
func (s *Store) VerifyAuditChain() (int, string, error) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	rows, err := s.db.Query(`SELECT id, ts, user, action, detail, ip, hash FROM audit ORDER BY id`)
	if err != nil {
		return 0, "", err
	}
	defer rows.Close()
	prev, checked := "", 0
	for rows.Next() {
		var id int64
		var ts, user, action, detail, ip, hash string
		if err := rows.Scan(&id, &ts, &user, &action, &detail, &ip, &hash); err != nil {
			return checked, "", err
		}
		if hash == "" {
			if checked == 0 && prev == "" {
				continue // pre-chain row from an older database
			}
			return checked, fmt.Sprintf("entry %d has no hash", id), nil
		}
		if auditHash(prev, ts, user, action, detail, ip) != hash {
			return checked, fmt.Sprintf("entry %d no longer matches", id), nil
		}
		prev = hash
		checked++
	}
	if err := rows.Err(); err != nil {
		return checked, "", err
	}
	head, err := s.GetSetting(auditHeadKey)
	if err != nil {
		return checked, "", err
	}
	if head != "" && head != prev {
		return checked, "the newest entries were removed", nil
	}
	return checked, "", nil
}

// ListAudit returns recent audit entries.
func (s *Store) ListAudit(limit int) ([]model.AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT a.id, a.ts, a.user, a.action, a.detail, a.ip, COALESCE(s.entity, '')
		FROM audit a LEFT JOIN audit_snapshots s ON s.audit_id = a.id
		WHERE (? = 0 OR a.site_id = ?)
		ORDER BY a.id DESC LIMIT ?`, s.site, s.site, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AuditEntry{}
	for rows.Next() {
		var e model.AuditEntry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.User, &e.Action, &e.Detail, &e.IP, &e.Entity); err != nil {
			return nil, err
		}
		e.TS = parseStamp(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListAuditAll returns every audit entry, oldest first, for a full export.
//
// shortcut: the whole table is loaded at once; stream it if an install ever
// grows past a few hundred thousand entries.
func (s *Store) ListAuditAll() ([]model.AuditEntry, error) {
	rows, err := s.db.Query(`SELECT id, ts, user, action, detail, ip FROM audit WHERE (? = 0 OR site_id = ?) ORDER BY id`, s.site, s.site)
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
