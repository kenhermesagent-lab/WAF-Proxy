// Package threatintel enriches a source address with third-party registries:
// RDAP for network ownership (keyless) and AbuseIPDB for abuse reports (one key
// per host). Both are optional: a console with no network access simply shows
// the local view.
package threatintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
)

// Settings keys. The key is sealed with the console's master key and the quota
// is the last rate-limit block AbuseIPDB reported, kept so the settings page can
// show the allowance after a restart.
const (
	KeyKey   = "abuseipdb_key"
	KeyQuota = "abuseipdb_quota"
)

// TTL is how long a lookup is reused. AbuseIPDB spends one check per lookup, so
// a busy console must not look the same address up on every page open.
const TTL = 6 * time.Hour

const (
	maxBody     = 256 << 10
	maxEntries  = 500
	abuseMaxAge = 90
)

// RDAP is the network registration for an address. Fields are strings because
// they are shown to an operator, not compared.
type RDAP struct {
	Network    string `json:"network,omitempty"`
	Name       string `json:"name,omitempty"`
	Org        string `json:"org,omitempty"`
	Abuse      string `json:"abuse,omitempty"`
	Registered string `json:"registered,omitempty"`
	Registry   string `json:"registry,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Abuse is the AbuseIPDB check result.
type Abuse struct {
	Score        int    `json:"score"`
	Reports      int    `json:"reports"`
	Reporters    int    `json:"reporters"`
	LastReported string `json:"last_reported,omitempty"`
	UsageType    string `json:"usage_type,omitempty"`
	ISP          string `json:"isp,omitempty"`
	Domain       string `json:"domain,omitempty"`
	Country      string `json:"country,omitempty"`
	Error        string `json:"error,omitempty"`
}

// Quota is the rate-limit block AbuseIPDB answers with on every check. The API
// does not name the plan, so the allowance is the only way to tell the tiers
// apart.
type Quota struct {
	Limit     int    `json:"limit"`
	Remaining int    `json:"remaining"`
	ResetAt   string `json:"reset_at,omitempty"`
}

// Result is one address as the console shows it.
type Result struct {
	IP     string    `json:"ip"`
	At     time.Time `json:"at"`
	Cached bool      `json:"cached"`
	RDAP   RDAP      `json:"rdap"`
	Abuse  *Abuse    `json:"abuse,omitempty"`
	Quota  *Quota    `json:"quota,omitempty"`
}

type entry struct {
	at  time.Time
	res Result
}

// Client performs and caches the lookups. BaseURLs are fields so tests can
// point the client at a local server instead of the public APIs.
type Client struct {
	HTTP     *http.Client
	RDAPBase string
	// LookupBase is the check endpoint; a trailing query string is the caller's
	// business, so the base carries no parameters.
	LookupBase string
	TTL        time.Duration
	Now        func() time.Time

	mu       sync.Mutex
	cache    map[string]entry
	inflight map[string]chan struct{}
	quota    *Quota
}

// New returns a client with production endpoints.
func New() *Client {
	return &Client{
		HTTP:       &http.Client{Timeout: 9 * time.Second},
		RDAPBase:   "https://rdap.org/ip/",
		LookupBase: "https://api.abuseipdb.com/api/v2/check",
		TTL:        TTL,
		Now:        time.Now,
		cache:      map[string]entry{},
		inflight:   map[string]chan struct{}{},
	}
}

// Configure changes the endpoints; tests use it to keep the network out.
func (c *Client) Configure(rdap, lookup string) {
	if rdap != "" {
		c.RDAPBase = rdap
	}
	if lookup != "" {
		c.LookupBase = lookup
	}
}

// Reset drops every cached answer and the last quota. It is called when the key
// changes, because the cached reports were bought with the previous allowance.
func (c *Client) Reset() {
	c.mu.Lock()
	c.cache = map[string]entry{}
	c.quota = nil
	c.mu.Unlock()
}

// SetQuota seeds the last known quota from storage.
func (c *Client) SetQuota(q *Quota) {
	c.mu.Lock()
	c.quota = q
	c.mu.Unlock()
}

// Quota returns the last rate-limit block, if any.
func (c *Client) Quota() *Quota {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.quota == nil {
		return nil
	}
	q := *c.quota
	return &q
}

// Lookup returns RDAP always and AbuseIPDB when a key is set. Cached results
// are returned without spending another check.
func (c *Client) Lookup(ctx context.Context, ip string, key string) (Result, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return Result{}, errors.New("not an IP address")
	}
	ip = addr.String()
	now := c.now()

	c.mu.Lock()
	if hit, ok := c.cache[ip]; ok && now.Sub(hit.at) < c.ttl() {
		c.mu.Unlock()
		res := hit.res
		res.Cached = true
		return res, nil
	}
	if wait, ok := c.inflight[ip]; ok {
		c.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return Result{}, ctx.Err()
		}
		c.mu.Lock()
		hit, ok := c.cache[ip]
		c.mu.Unlock()
		if !ok {
			return Result{}, errors.New("lookup failed")
		}
		res := hit.res
		res.Cached = true
		return res, nil
	}
	done := make(chan struct{})
	c.inflight[ip] = done
	c.mu.Unlock()

	res := Result{IP: ip, At: now}
	if c.RDAPBase != "" {
		res.RDAP = c.rdap(ctx, ip)
	}
	if key != "" {
		abuse, quota, err := c.abuse(ctx, ip, key)
		res.Abuse, res.Quota = abuse, quota
		if err != nil {
			// A transport or quota failure is not a lookup worth caching: the
			// next open should try again.
			res.Abuse = &Abuse{Error: err.Error()}
		}
	}

	c.mu.Lock()
	delete(c.inflight, ip)
	if res.Abuse == nil || res.Abuse.Error == "" {
		c.store(ip, res)
	}
	c.mu.Unlock()
	close(done)
	return res, nil
}

func (c *Client) store(ip string, res Result) {
	if c.cache == nil {
		c.cache = map[string]entry{}
	}
	if len(c.cache) >= maxEntries {
		oldestKey := ""
		var oldest time.Time
		for k, v := range c.cache {
			if oldestKey == "" || v.at.Before(oldest) {
				oldestKey, oldest = k, v.at
			}
		}
		delete(c.cache, oldestKey)
	}
	c.cache[ip] = entry{at: res.At, res: res}
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) ttl() time.Duration {
	if c.TTL > 0 {
		return c.TTL
	}
	return TTL
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// rdap asks rdap.org, which redirects to the RIR that owns the address.
func (c *Client) rdap(ctx context.Context, ip string) RDAP {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.RDAPBase+url.PathEscape(ip), nil)
	if err != nil {
		return RDAP{Error: "cannot build the RDAP request"}
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", "WAF-Proxy")
	resp, err := c.client().Do(req)
	if err != nil {
		return RDAP{Error: "rdap.org did not answer"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return RDAP{Error: fmt.Sprintf("RDAP answered HTTP %d", resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return RDAP{Error: "cannot read the RDAP answer"}
	}
	var doc rdapDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return RDAP{Error: "RDAP sent an unexpected answer"}
	}
	out := RDAP{
		Network:    doc.network(),
		Name:       first(doc.Name, doc.Handle),
		Org:        doc.org(),
		Abuse:      doc.abuseEmail(),
		Registered: doc.event("registration"),
	}
	if resp.Request != nil && resp.Request.URL != nil {
		out.Registry = registryName(resp.Request.URL.Hostname())
	}
	return out
}

func (c *Client) abuse(ctx context.Context, ip, key string) (*Abuse, *Quota, error) {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()
	q := url.Values{}
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", fmt.Sprint(abuseMaxAge))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.LookupBase+"?"+q.Encode(), nil)
	if err != nil {
		return nil, nil, errors.New("cannot build the AbuseIPDB request")
	}
	req.Header.Set("Key", key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "WAF-Proxy")
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, nil, errors.New("AbuseIPDB did not answer")
	}
	defer resp.Body.Close()
	quota := quotaFrom(resp.Header)
	if quota != nil {
		c.mu.Lock()
		c.quota = quota
		c.mu.Unlock()
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, quota, errors.New("cannot read the AbuseIPDB answer")
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusTooManyRequests:
		return nil, quota, errors.New("AbuseIPDB daily quota is spent; it resets at " + quotaClock(quota))
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, quota, errors.New("AbuseIPDB refused the key; save a valid key in Settings")
	default:
		return nil, quota, fmt.Errorf("AbuseIPDB answered HTTP %d", resp.StatusCode)
	}
	var doc abuseDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, quota, errors.New("AbuseIPDB sent an unexpected answer")
	}
	d := doc.Data
	out := &Abuse{
		Score:     d.AbuseConfidenceScore,
		Reports:   d.TotalReports,
		Reporters: d.NumDistinctUsers,
		UsageType: d.UsageType,
		ISP:       d.ISP,
		Domain:    d.Domain,
		Country:   d.CountryCode,
	}
	if d.LastReportedAt != "" {
		if at, err := time.Parse(time.RFC3339, d.LastReportedAt); err == nil {
			out.LastReported = at.UTC().Format(time.RFC3339)
		}
	}
	return out, quota, nil
}

// quotaFrom reads the rate-limit block every check answers with. A missing or
// unparsable header leaves the field at zero rather than guessing.
func quotaFrom(h http.Header) *Quota {
	// Without a ceiling there is no plan to infer and no bar to draw, so a
	// partial header block is ignored rather than shown as 0 of 0.
	limit, ok := atoiHeader(h.Get("X-RateLimit-Limit"))
	if !ok || limit <= 0 {
		return nil
	}
	remaining, _ := atoiHeader(h.Get("X-RateLimit-Remaining"))
	return &Quota{Limit: limit, Remaining: remaining, ResetAt: h.Get("X-RateLimit-Reset")}
}

func atoiHeader(v string) (int, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

func quotaClock(q *Quota) string {
	if q == nil || q.ResetAt == "" {
		return "the next UTC midnight"
	}
	if at, err := time.Parse(time.RFC3339, q.ResetAt); err == nil {
		return at.UTC().Format("15:04 UTC")
	}
	return q.ResetAt
}

// Plan is the allowance a key carries. AbuseIPDB does not name the plan in its
// answer, so the tier is inferred from the rate-limit ceiling.
type Plan struct {
	Name         string `json:"name"`
	ChecksPerDay int    `json:"checks_per_day"`
}

var plans = []Plan{
	{Name: "Individual (free)", ChecksPerDay: 1000},
	{Name: "Webmaster", ChecksPerDay: 3000},
	{Name: "Supporter", ChecksPerDay: 5000},
	{Name: "Basic", ChecksPerDay: 10000},
	{Name: "Premium", ChecksPerDay: 50000},
}

// PlanFor maps a rate-limit ceiling to a plan, or returns nil when the ceiling
// matches none of them.
func PlanFor(limit int) *Plan {
	for i := range plans {
		if plans[i].ChecksPerDay == limit {
			p := plans[i]
			return &p
		}
	}
	return nil
}

// Quota setting codec. The page never receives the key; it sees a tail and a
// saved flag instead.

// LoadKey opens the sealed key. An unreadable value is reported as no key, so
// the console asks for one again instead of failing the page.
func LoadKey(kv map[string]string, box *wfcrypto.Box) string {
	sealed := strings.TrimSpace(kv[KeyKey])
	if sealed == "" || box == nil {
		return ""
	}
	key, err := box.Open(sealed)
	if err != nil {
		return ""
	}
	return key
}

// SealKey encrypts a key for storage.
func SealKey(box *wfcrypto.Box, key string) (string, error) {
	if box == nil {
		return "", errors.New("the console has no master key")
	}
	return box.Seal(key)
}

// ValidKey keeps a pasted value to something that can be sent as a header and
// cannot smuggle a newline into the request.
func ValidKey(key string) bool {
	if len(key) < 20 || len(key) > 200 {
		return false
	}
	for _, c := range key {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.', c == '=':
		default:
			return false
		}
	}
	return true
}

// DecodeQuota reads the stored quota; an unreadable row is ignored.
func DecodeQuota(raw string) *Quota {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var q Quota
	if err := json.Unmarshal([]byte(raw), &q); err != nil {
		return nil
	}
	return &q
}

// EncodeQuota stores a quota block, or "" to clear it.
func EncodeQuota(q *Quota) string {
	if q == nil {
		return ""
	}
	blob, _ := json.Marshal(q)
	return string(blob)
}

func registryName(host string) string {
	switch {
	case strings.HasSuffix(host, "ripe.net"):
		return "RIPE NCC"
	case strings.HasSuffix(host, "arin.net"):
		return "ARIN"
	case strings.HasSuffix(host, "apnic.net"):
		return "APNIC"
	case strings.HasSuffix(host, "lacnic.net"):
		return "LACNIC"
	case strings.HasSuffix(host, "afrinic.net"):
		return "AFRINIC"
	}
	return strings.TrimPrefix(host, "rdap.")
}

func first(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// rdapDoc is the subset of an RDAP answer the console reads. The format puts
// names in vCard arrays, so the helpers below pick the fields out.
type rdapDoc struct {
	Handle    string `json:"handle"`
	Name      string `json:"name"`
	Start     string `json:"startAddress"`
	End       string `json:"endAddress"`
	IPVersion string `json:"ipVersion"`
	CIDR0     []struct {
		Length int `json:"length"`
	} `json:"cidr0_cidrs"`
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities []struct {
		Roles      []string          `json:"roles"`
		VCardArray []json.RawMessage `json:"vcardArray"`
	} `json:"entities"`
}

func (d rdapDoc) network() string {
	if d.Start != "" && d.End != "" {
		return d.Start + " – " + d.End
	}
	if len(d.CIDR0) > 0 {
		return fmt.Sprintf("/%d", d.CIDR0[0].Length)
	}
	return ""
}

func (d rdapDoc) event(action string) string {
	for _, e := range d.Events {
		if e.Action == action && e.Date != "" {
			if at, err := time.Parse(time.RFC3339, e.Date); err == nil {
				return at.UTC().Format("2006-01-02")
			}
			return e.Date
		}
	}
	return ""
}

// org is the registrant's display name, falling back to any entity with one.
func (d rdapDoc) org() string {
	fallback := ""
	for _, e := range d.Entities {
		name := vcardText(e.VCardArray, "fn")
		if name == "" {
			continue
		}
		for _, role := range e.Roles {
			if role == "registrant" {
				return name
			}
		}
		if fallback == "" {
			fallback = name
		}
	}
	return fallback
}

func (d rdapDoc) abuseEmail() string {
	for _, e := range d.Entities {
		for _, role := range e.Roles {
			if role != "abuse" {
				continue
			}
			if mail := vcardText(e.VCardArray, "email"); mail != "" {
				return mail
			}
		}
	}
	return ""
}

// vcardText finds a field in ["vcard", [[name, params, type, value], ...]].
func vcardText(raw []json.RawMessage, field string) string {
	if len(raw) < 2 {
		return ""
	}
	var rows [][]json.RawMessage
	if err := json.Unmarshal(raw[1], &rows); err != nil {
		return ""
	}
	for _, row := range rows {
		if len(row) < 4 {
			continue
		}
		var name, value string
		if json.Unmarshal(row[0], &name) != nil || json.Unmarshal(row[3], &value) != nil {
			continue
		}
		if name == field {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

type abuseDoc struct {
	Data struct {
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		TotalReports         int    `json:"totalReports"`
		NumDistinctUsers     int    `json:"numDistinctUsers"`
		LastReportedAt       string `json:"lastReportedAt"`
		UsageType            string `json:"usageType"`
		ISP                  string `json:"isp"`
		Domain               string `json:"domain"`
		CountryCode          string `json:"countryCode"`
	} `json:"data"`
}

// LocalIP is the loopback address used for a "check the key" probe: it costs
// one lookup and cannot describe any real visitor.
const LocalIP = "127.0.0.1"
