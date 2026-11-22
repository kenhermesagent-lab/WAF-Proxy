// Package model holds the domain types shared by the store, API and proxy.
package model

import "time"

// Proxy is a hostname routed through the gateway.
type Proxy struct {
	ID                  int64     `json:"id"`
	Hostname            string    `json:"hostname"`
	Enabled             bool      `json:"enabled"`
	CertID              *int64    `json:"cert_id,omitempty"`
	ProfileID           *int64    `json:"profile_id,omitempty"`
	ProtectionProfileID *int64    `json:"protection_profile_id,omitempty"`
	AccessProfileID     *int64    `json:"access_profile_id,omitempty"`
	GateMode            string    `json:"gate_mode"` // off | passphrase | accounts | accounts_totp | forward_auth
	GateSecret          string    `json:"-"`         // argon2 hash, write-only in the API
	AuthProviderID      *int64    `json:"auth_provider_id,omitempty"`
	GateTOTPHint        string    `json:"gate_totp_hint,omitempty"`
	Fingerprint         string    `json:"fingerprint"` // strict | minimal
	BotLevel            string    `json:"bot_level"`   // off | light | standard | aggressive
	Maintenance         bool      `json:"maintenance"`
	WAFMode             string    `json:"waf_mode"` // inherit | off | detect | block
	CreatedAt           time.Time `json:"created_at"`
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
}

// Profile is a WAF protection profile.
type Profile struct {
	ID             int64  `json:"id"`
	Name           string `json:"name"`
	Builtin        bool   `json:"builtin"`
	Mode           string `json:"mode"` // detect | block
	Paranoia       int    `json:"paranoia"`
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
}

// Certificate renewal policies.
const (
	CertRenewMonthly      = "monthly"
	CertRenewEvery2Months = "every_2_months"
	CertRenewEvery3Months = "every_3_months"
	CertRenewBeforeExpiry = "before_expiry"
)

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
	LastError string     `json:"last_error,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
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
	ASN       int       `json:"asn"`
	Lat       float64   `json:"lat"`
	Lon       float64   `json:"lon"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
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

// AuditEntry records an administrative mutation.
type AuditEntry struct {
	ID     int64     `json:"id"`
	TS     time.Time `json:"ts"`
	User   string    `json:"user"`
	Action string    `json:"action"`
	Detail string    `json:"detail"`
	IP     string    `json:"ip"`
}

// Verdict is the outcome of the policy pipeline.
type Verdict struct {
	Action    string `json:"action"`
	Stage     string `json:"stage"`
	Rule      string `json:"rule"`
	Reason    string `json:"reason"`
	Status    int    `json:"status"`
	BanSource string `json:"ban_source,omitempty"`
}
