// Package model holds the domain types shared by the store, API and proxy.
package model

import "time"

// Proxy is a hostname routed through the gateway.
type Proxy struct {
	ID           int64     `json:"id"`
	Hostname     string    `json:"hostname"`
	Enabled      bool      `json:"enabled"`
	CertID       *int64    `json:"cert_id,omitempty"`
	ProfileID    *int64    `json:"profile_id,omitempty"`
	GateMode     string    `json:"gate_mode"` // off | passphrase | accounts | accounts_totp
	GateSecret   string    `json:"-"`         // argon2 hash, write-only in the API
	GateTOTPHint string    `json:"gate_totp_hint,omitempty"`
	Fingerprint  string    `json:"fingerprint"` // strict | minimal
	BotLevel     string    `json:"bot_level"`   // off | light | standard | aggressive
	Maintenance  bool      `json:"maintenance"`
	WAFMode      string    `json:"waf_mode"` // inherit | off | detect | block
	CreatedAt    time.Time `json:"created_at"`
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
	LastError string     `json:"last_error,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// Policy kinds.
const (
	PolicyIPWhitelist      = "ip_whitelist"
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
	Source    string     `json:"source"` // manual | scan | waf | bot | crowdsec | feed | decoy | gate
	Permanent bool       `json:"permanent"`
	Hits      int64      `json:"hits"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Feed is an external threat-intelligence list.
type Feed struct {
	ID           int64      `json:"id"`
	Name         string     `json:"name"`
	URL          string     `json:"url"`
	Action       string     `json:"action"` // block | challenge | log
	IntervalS    int        `json:"interval_s"`
	Enabled      bool       `json:"enabled"`
	Builtin      bool       `json:"builtin"`
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

// Alert is a queued notification.
type Alert struct {
	ID        int64
	Channel   string
	Kind      string
	Dedupe    string
	Payload   string
	State     string
	Attempts  int
	CreatedAt time.Time
	SentAt    *time.Time
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
