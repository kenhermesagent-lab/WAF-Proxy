// Package model holds the domain types shared by the store, API and proxy.
package model

import "time"

// DefaultMaxBody is the request-body ceiling a new install starts with. Every
// body is buffered so the WAF can inspect it, which is why the buffered byte
// budget — not this value — is what bounds total memory.
const DefaultMaxBody = 64 << 20

// MaxBodyCeiling bounds the setting. A body above the buffered byte budget
// (WAFPROXY_MAX_BUFFERED_BYTES, 512 MiB by default) is refused with a 503, so a
// larger ceiling only takes effect once that budget is raised too.
const MaxBodyCeiling = 1 << 30

// BodySkip is one request path whose body streams to the upstream without being
// buffered or inspected. ListIDs narrows the exemption to sources named by
// those lists, so an operator can trust a CIDR instead of the whole internet.
type BodySkip struct {
	Method  string  `json:"method"`
	Prefix  string  `json:"prefix"`
	ListIDs []int64 `json:"list_ids,omitempty"`
}

// Proxy is a hostname routed through the gateway.
type Proxy struct {
	ID                  int64  `json:"id"`
	SiteID              int64  `json:"site_id,omitempty"`
	Hostname            string `json:"hostname"`
	Enabled             bool   `json:"enabled"`
	CertID              *int64 `json:"cert_id,omitempty"`
	ProfileID           *int64 `json:"profile_id,omitempty"`
	ProtectionProfileID *int64 `json:"protection_profile_id,omitempty"`
	AccessProfileID     *int64 `json:"access_profile_id,omitempty"`
	GateMode            string `json:"gate_mode"` // off | passphrase | accounts | accounts_totp | forward_auth
	GateSecret          string `json:"-"`         // argon2 hash, write-only in the API
	AuthProviderID      *int64 `json:"auth_provider_id,omitempty"`
	GateTOTPHint        string `json:"gate_totp_hint,omitempty"`
	Fingerprint         string `json:"fingerprint"` // strict | minimal
	BotLevel            string `json:"bot_level"`   // off | light | standard | aggressive
	Maintenance         bool   `json:"maintenance"`
	WAFMode             string `json:"waf_mode"` // inherit | off | detect | block
	// Balancing and health settings apply to every upstream of the site unless
	// an upstream overrides them. Empty values mean the defaults.
	LBPolicy        string `json:"lb_policy"`
	HealthPath      string `json:"health_path"`
	HealthExpect    string `json:"health_expect"`
	HealthInterval  int    `json:"health_interval"`
	HealthFailAfter int    `json:"health_fail_after"`
	// MaxInflight and MaxInflightPerClient bound this site; zero inherits the
	// process-wide budget.
	MaxInflight          int `json:"max_inflight"`
	MaxInflightPerClient int `json:"max_inflight_per_client"`
	// MaxBody bounds the buffered request body for this site. Zero inherits the
	// host-wide ceiling; a body-skip path is not bounded because it is streamed.
	MaxBody int64 `json:"max_body"`
	// BodySkip paths stream their body without inspection. Method, path and
	// header rules, lists, rate limits, bans and the access gate still apply.
	BodySkip []BodySkip `json:"body_skip"`
	// UpstreamTimeout bounds a whole upstream exchange in seconds; zero keeps
	// the transport default. Retries applies to idempotent requests only.
	UpstreamTimeout int `json:"upstream_timeout"`
	Retries         int `json:"retries"`
	// TLSMinVersion is "1.2" (default) or "1.3" for this site.
	TLSMinVersion   string     `json:"tls_min_version"`
	RequestHeaders  []HeaderOp `json:"request_headers"`
	ResponseHeaders []HeaderOp `json:"response_headers"`
	CreatedAt       time.Time  `json:"created_at"`
}

// HeaderOp is one request or response header rewrite: set, add or remove.
type HeaderOp struct {
	Action string `json:"action"`
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
}

// Delivery is one queued webhook payload for an agent link.
type Delivery struct {
	ID            int64      `json:"id"`
	LinkID        int64      `json:"link_id"`
	EventID       int64      `json:"event_id"`
	Kind          string     `json:"kind"`
	Body          string     `json:"-"`
	State         string     `json:"state"` // pending | delivered | failed
	Attempts      int        `json:"attempts"`
	NextAttemptAt time.Time  `json:"next_attempt_at"`
	LastStatus    int        `json:"last_status"`
	LastError     string     `json:"last_error,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	DeliveredAt   *time.Time `json:"delivered_at,omitempty"`
}

// AgentLink is a webhook an external agent listens on: the console pushes
// signed events there and the agent decides what to do.
type AgentLink struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Endpoint  string    `json:"endpoint"`
	Secret    string    `json:"-"`
	HasSecret bool      `json:"has_secret"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	// LastDelivery is the newest payload state, so an operator can see whether
	// the agent is actually receiving events without opening the log.
	LastDelivery *DeliverySummary `json:"last_delivery,omitempty"`
}

// DeliverySummary is the last-delivery status shown on an agent link.
type DeliverySummary struct {
	ID          int64      `json:"id"`
	Kind        string     `json:"kind"`
	State       string     `json:"state"`
	Attempts    int        `json:"attempts"`
	LastStatus  int        `json:"last_status"`
	LastError   string     `json:"last_error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	DeliveredAt *time.Time `json:"delivered_at,omitempty"`
}

// AnomalyEvent is one detection: a traffic, egress or login-failure condition
// that crossed its threshold for a proxy.
type AnomalyEvent struct {
	ID             int64      `json:"id"`
	Kind           string     `json:"kind"` // egress_spike | rate_spike | auth_burst
	ProxyID        int64      `json:"proxy_id"`
	ProxyHost      string     `json:"proxy_host"`
	WindowStart    time.Time  `json:"window_start"`
	WindowSeconds  int        `json:"window_seconds"`
	Value          float64    `json:"value"`
	Baseline       float64    `json:"baseline"`
	Detail         string     `json:"detail"`
	State          string     `json:"state"` // open | acknowledged
	CreatedAt      time.Time  `json:"created_at"`
	LastSeen       time.Time  `json:"last_seen"`
	AcknowledgedBy string     `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
}

// AuthProvider is an external forward-auth endpoint — Authelia, authentik or any
// server that answers 2xx for an authenticated session — that a proxy can hand
// its access gate to.
type AuthProvider struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`       // authelia | authentik | generic
	VerifyURL string `json:"verify_url"` // forward-auth endpoint, e.g. http://authelia:9091/api/verify
	LoginURL  string `json:"login_url"`  // portal an unauthenticated visitor is sent to
	Header    string `json:"header"`     // header carrying the shared secret
	Secret    string `json:"-"`          // sealed, write-only in the API
	HasSecret bool   `json:"has_secret"`
}

// ProtectionProfile is a named set of response-hardening options a proxy can
// apply, so a site gets HSTS, clickjacking and MIME-sniffing protection without
// every application having to set its own headers.
type ProtectionProfile struct {
	ID                int64  `json:"id"`
	Name              string `json:"name"`
	Builtin           bool   `json:"builtin"`
	ForceHTTPS        bool   `json:"force_https"`
	HSTS              bool   `json:"hsts"`
	HSTSSubdomains    bool   `json:"hsts_subdomains"`
	FrameOptions      string `json:"frame_options"` // off | deny | sameorigin
	NoSniff           bool   `json:"nosniff"`
	ReferrerPolicy    string `json:"referrer_policy"`
	CSP               string `json:"csp"`
	PermissionsPolicy string `json:"permissions_policy"`
	HideServer        bool   `json:"hide_server"`
}

// Access rule roles. A rule references a list and says what that list means to
// this one profile: an allow list narrows access to the addresses on it, a deny
// list removes them. "inherit" uses the list's own kind.
const (
	AccessRoleAllow   = "allow"
	AccessRoleDeny    = "deny"
	AccessRoleInherit = "inherit"
)

// AccessRule is one list reference inside an access profile.
type AccessRule struct {
	PolicyID int64  `json:"policy_id"`
	Role     string `json:"role"` // allow | deny | inherit
}

// Named access lists. A blocklist denies the addresses and countries it holds
// for every host whose access profile attaches it; a whitelist makes that host
// reachable only from them.
const (
	ListKindBlock = "blocklist"
	ListKindAllow = "whitelist"
)

// AccessList is a named set of IP/CIDR and country entries that an access
// profile attaches as a whole.
type AccessList struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"` // blocklist | whitelist
	Name      string    `json:"name"`
	IPs       string    `json:"ips"`       // comma separated IPs and CIDRs
	Countries string    `json:"countries"` // comma separated ISO 3166-1 alpha-2
	CreatedAt time.Time `json:"created_at"`
}

// AccessProfile is a complete per-site policy: the lists it applies (each as
// an allow or deny list), the named block/allow lists it attaches, and the
// protection profiles that go with them. A proxy selects one, so an operator
// chooses a single thing when creating a host instead of matching three lists
// by hand.
type AccessProfile struct {
	ID                  int64        `json:"id"`
	Name                string       `json:"name"`
	Rules               []AccessRule `json:"rules"`
	ListIDs             []int64      `json:"list_ids"`
	WAFProfileID        *int64       `json:"waf_profile_id,omitempty"`
	ProtectionProfileID *int64       `json:"protection_profile_id,omitempty"`
}

// PolicyIDs returns the referenced list IDs, for callers that only need them.
func (a AccessProfile) PolicyIDs() []int64 {
	out := make([]int64, 0, len(a.Rules))
	for _, r := range a.Rules {
		out = append(out, r.PolicyID)
	}
	return out
}

// Upstream is a backend server for a proxy.
type Upstream struct {
	ID      int64  `json:"id"`
	ProxyID int64  `json:"proxy_id"`
	URL     string `json:"url"`
	Weight  int    `json:"weight"`
	Enabled bool   `json:"enabled"`
	// MaxConns caps concurrent requests to this upstream; zero means no cap.
	MaxConns int `json:"max_conns"`
}

// RouteKind enumerates non-proxy route behaviours.
const (
	RouteRedirect = "redirect"
	RouteAlias    = "alias"
)

// Route is a redirect or alias attached to a proxy.
type Route struct {
	ID          int64  `json:"id"`
	ProxyID     int64  `json:"proxy_id"`
	Kind        string `json:"kind"`
	Match       string `json:"match"`
	Target      string `json:"target"`
	StripPrefix bool   `json:"strip_prefix"`
	Priority    int    `json:"priority"`
	// Request matchers. Empty fields match everything; a route with more
	// matchers is only chosen when all of them agree.
	Method string `json:"method,omitempty"`
	Header string `json:"header,omitempty"` // "Name: value"
	Query  string `json:"query,omitempty"`  // "name=value"
	Regex  bool   `json:"regex,omitempty"`
	// Upstream overrides the site's pool for this route. Timeout bounds the
	// exchange in seconds. Status is the redirect code (301, 307 or 308).
	Upstream string `json:"upstream,omitempty"`
	Timeout  int    `json:"timeout,omitempty"`
	Status   int    `json:"status,omitempty"`
}

// Profile is a WAF protection profile.
type Profile struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Builtin  bool   `json:"builtin"`
	Mode     string `json:"mode"` // detect | block
	Paranoia int    `json:"paranoia"`
	// Responses is off, flag or block: whether upstream responses are run
	// through the CRS response rules before they reach the browser.
	Responses      string `json:"responses"`
	Anomaly        int    `json:"anomaly"`
	AllowedMethods string `json:"allowed_methods"`
	MaxBody        int64  `json:"max_body"`
	Exceptions     string `json:"exceptions"` // comma separated CRS rule IDs
	// MaxResponse cuts an upstream response instead of streaming it without
	// bound; 0 leaves it unlimited.
	MaxResponse int64 `json:"max_response"`
	// LoginPaths are the path prefixes that take credentials. They get their own
	// token bucket so credential stuffing is throttled before it reaches the
	// application, whose own login may have no limit at all.
	LoginPaths string `json:"login_paths"`
	LoginRPS   int    `json:"login_rps"`
	LoginBurst int    `json:"login_burst"`
	// AdminPaths are the path prefixes that only the addresses in AdminIPs may
	// reach. An empty AdminIPs leaves the rule inert.
	AdminPaths string `json:"admin_paths"`
	AdminIPs   string `json:"admin_ips"`
	// BundleModes maps an installed signature bundle to off, log or block for
	// this profile. A bundle with no entry logs only, so installing a bundle
	// never starts refusing traffic on its own.
	BundleModes map[string]string `json:"bundle_modes"`
}

// Bundle modes. Off skips the pack's rules for this profile, log records the
// match without refusing it, block refuses it.
const (
	BundleOff   = "off"
	BundleLog   = "log"
	BundleBlock = "block"
)

// ValidBundleMode reports whether mode is an accepted bundle mode.
func ValidBundleMode(mode string) bool {
	switch mode {
	case BundleOff, BundleLog, BundleBlock:
		return true
	}
	return false
}

// BundleMode returns the mode for one bundle on this profile, defaulting to
// log so an unconfigured bundle is visible in the hit table but never blocks.
func (p *Profile) BundleMode(name string) string {
	if p != nil {
		if mode, ok := p.BundleModes[name]; ok && ValidBundleMode(mode) {
			return mode
		}
	}
	return BundleLog
}

// Certificate sources shown in the inventory.
const (
	CertSourceACME     = "acme"
	CertSourceUploaded = "uploaded"
	CertSourceInternal = "internal"
)

// Certificate renewal policies.
const (
	CertRenewMonthly      = "monthly"
	CertRenewEvery2Months = "every_2_months"
	CertRenewEvery3Months = "every_3_months"
	CertRenewBeforeExpiry = "before_expiry"
)

// Certificate challenge types. DNS-01 needs no inbound port; HTTP-01 needs
// port 80 and TLS-ALPN-01 needs the TLS listener to answer the acme-tls/1 ALPN.
const (
	CertChallengeDNS     = "dns-01"
	CertChallengeHTTP    = "http-01"
	CertChallengeTLSALPN = "tls-alpn-01"
)

// ValidCertChallenge reports whether mode is an accepted ACME challenge.
func ValidCertChallenge(mode string) bool {
	switch mode {
	case CertChallengeDNS, CertChallengeHTTP, CertChallengeTLSALPN:
		return true
	}
	return false
}

// ValidCertRenewMode reports whether mode is an accepted renewal policy.
func ValidCertRenewMode(mode string) bool {
	switch mode {
	case CertRenewMonthly, CertRenewEvery2Months, CertRenewEvery3Months, CertRenewBeforeExpiry:
		return true
	}
	return false
}

// Cert is a TLS certificate managed by the ACME client.
type Cert struct {
	ID        int64      `json:"id"`
	Domains   string     `json:"domains"`
	Provider  string     `json:"provider"`
	Status    string     `json:"status"`
	IssuedAt  *time.Time `json:"issued_at,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CertPEM   []byte     `json:"-"`
	KeyPEM    []byte     `json:"-"`
	Wildcard  bool       `json:"wildcard"`
	RenewMode string     `json:"renew_mode"`
	Challenge string     `json:"challenge"`
	LastError string     `json:"last_error,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	// Source is where the certificate came from: acme, uploaded or internal.
	Source string `json:"source"`
}

// Policy kinds.
const (
	PolicyIPWhitelist      = "ip_whitelist"
	PolicyIPBlacklist      = "ip_blacklist"
	PolicyCountryWhitelist = "country_whitelist"
	PolicyCountryBlacklist = "country_blacklist"
	PolicyASNBlock         = "asn_block"
	PolicyDecoy            = "decoy"
)

// Role is a named set of administrator permissions. Permissions are
// "area.action" strings; "*" is every permission.
type Role struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Builtin     bool     `json:"builtin"`
	Permissions []string `json:"permissions"`
}

// Policy is a single allow/deny rule evaluated before routing.
type Policy struct {
	ID       int64  `json:"id"`
	Scope    string `json:"scope"` // global | proxy
	ProxyID  *int64 `json:"proxy_id,omitempty"`
	Kind     string `json:"kind"`
	Value    string `json:"value"`
	Action   string `json:"action"` // allow | block | challenge | log
	Priority int    `json:"priority"`
	Enabled  bool   `json:"enabled"`
	Note     string `json:"note"`
}

// Ban is a temporary or permanent IP block.
type Ban struct {
	ID        int64      `json:"id"`
	CIDR      string     `json:"cidr"`
	Reason    string     `json:"reason"`
	Source    string     `json:"source"` // manual | scan | waf | bot | crowdsec | feed | decoy | gate | mcp
	Permanent bool       `json:"permanent"`
	Hits      int64      `json:"hits"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Feed is an external threat-intelligence list or an uploaded local blocklist.
type Feed struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	Action    string `json:"action"` // block | challenge | log
	IntervalS int    `json:"interval_s"`
	Enabled   bool   `json:"enabled"`
	Builtin   bool   `json:"builtin"`
	Local     bool   `json:"local"`
	// AlwaysBlock feeds are enforced before the allow lists: they hold bans the
	// operator made permanent, which no whitelist may override.
	AlwaysBlock  bool       `json:"always_block"`
	Filename     string     `json:"filename,omitempty"`
	LocalPath    string     `json:"-"`
	ETag         string     `json:"-"`
	LastModified string     `json:"-"`
	LastFetch    *time.Time `json:"last_fetch,omitempty"`
	LastCount    int        `json:"last_count"`
	State        string     `json:"state"` // ok | frozen | error | pending
	LastError    string     `json:"last_error,omitempty"`
}

// Event is one audited request or policy decision.
type Event struct {
	ID        int64     `json:"id"`
	TS        time.Time `json:"ts"`
	ProxyID   *int64    `json:"proxy_id,omitempty"`
	Host      string    `json:"host"`
	SrcIP     string    `json:"src_ip"`
	Country   string    `json:"country"`
	City      string    `json:"city,omitempty"`
	ASN       int       `json:"asn"`
	Lat       float64   `json:"lat"`
	Lon       float64   `json:"lon"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Query     string    `json:"query,omitempty"`
	Status    int       `json:"status"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
	LatencyMS int64     `json:"latency_ms"`
	Stage     string    `json:"stage"`
	RuleID    string    `json:"rule_id"`
	RuleMsg   string    `json:"rule_msg"`
	Action    string    `json:"action"` // allow | block | challenge | ban | log
	UA        string    `json:"ua"`
	Sample    int       `json:"sample"`
	// RequestID follows one request from the edge through the pipeline.
	RequestID string `json:"request_id,omitempty"`
}

// Flow is an hourly traffic rollup.
type Flow struct {
	Hour     time.Time `json:"hour"`
	ProxyID  int64     `json:"proxy_id"`
	Reqs     int64     `json:"reqs"`
	BytesIn  int64     `json:"bytes_in"`
	BytesOut int64     `json:"bytes_out"`
	Blocked  int64     `json:"blocked"`
}

// GateUser is an account allowed through the per-proxy access gate.
type GateUser struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	TOTPSecret   string    `json:"-"`
	TOTPEnabled  bool      `json:"totp_enabled"`
	CreatedAt    time.Time `json:"created_at"`
}

// UsernameBan denies a gate username without deleting its account. It also
// invalidates any visitor sessions that account already has.
type UsernameBan struct {
	Username  string     `json:"username"`
	Reason    string     `json:"reason"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// GateSession is one live access-gate visitor session. Ref is a one-way hash of
// the session cookie, safe to show to an operator or an agent.
type GateSession struct {
	// ID is the session cookie value. It is intentionally never serialized.
	ID            string    `json:"-"`
	Ref           string    `json:"ref"`
	ProxyID       int64     `json:"proxy_id"`
	ProxyHostname string    `json:"proxy_hostname"`
	Username      string    `json:"username"`
	IP            string    `json:"ip"`
	UA            string    `json:"ua"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// MCPToken is an agent credential. Only its hash is stored; the plaintext is
// returned once when it is created.
type MCPToken struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	// Scopes lists the tool names this token may call. An empty list means
	// every tool, which keeps tokens created before scopes working.
	Scopes []string `json:"scopes"`
	// SiteID is the site the token acts on, and Site is its slug for display.
	// A token stored without a site reads the default site.
	SiteID int64  `json:"-"`
	Site   string `json:"site"`
}

// Alert is a queued notification.
type Alert struct {
	ID        int64      `json:"id"`
	Channel   string     `json:"channel"`
	Kind      string     `json:"kind"`
	Dedupe    string     `json:"dedupe,omitempty"`
	Payload   string     `json:"payload"`
	State     string     `json:"state"`
	Attempts  int        `json:"attempts"`
	CreatedAt time.Time  `json:"created_at"`
	SentAt    *time.Time `json:"sent_at,omitempty"`
}

// LogView is a named set of log filters kept on the server, so the whole team
// sees the same views instead of each browser keeping its own.
type LogView struct {
	Name      string    `json:"name"`
	Query     string    `json:"query"`
	UpdatedBy string    `json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AuditEntry records an administrative mutation.
type AuditEntry struct {
	ID     int64     `json:"id"`
	TS     time.Time `json:"ts"`
	User   string    `json:"user"`
	Action string    `json:"action"`
	Detail string    `json:"detail"`
	IP     string    `json:"ip"`
	// Entity is set when the entry carries a before/after snapshot.
	Entity string `json:"entity,omitempty"`
}

// AuditSnapshot is the state an audited mutation started from and left behind.
// Empty Before means the change created the entity; empty After means it was
// removed.
type AuditSnapshot struct {
	AuditID  int64  `json:"audit_id"`
	Entity   string `json:"entity"`
	EntityID int64  `json:"entity_id"`
	Before   string `json:"before,omitempty"`
	After    string `json:"after,omitempty"`
}

// Verdict is the outcome of the policy pipeline.
type Verdict struct {
	Action string `json:"action"`
	Stage  string `json:"stage"`
	Rule   string `json:"rule"`
	// List names the blocklist or whitelist that decided the request, so a log
	// row can say which list to edit instead of only "this site's profile".
	List      string `json:"list,omitempty"`
	Reason    string `json:"reason"`
	Status    int    `json:"status"`
	BanSource string `json:"ban_source,omitempty"`
}
