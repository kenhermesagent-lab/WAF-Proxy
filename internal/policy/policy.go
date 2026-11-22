// Package policy implements the ordered request pipeline that runs before any
// traffic reaches an upstream.
package policy

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/intel"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

// Settings is the cached global configuration.
type Settings struct {
	RPS            int
	Burst          int
	ASNBlock       bool
	StealthDrop    bool
	StealthPing    bool
	WANIface       string
	LANIface       string
	RetentionDays  int
	SampleAboveRPS int
	MaxBody        int64
	Enabled        bool
	DecoyHosts     map[string]bool
}

// Request is everything the pipeline needs about an incoming request.
type Request struct {
	Proxy  *model.Proxy
	Host   string
	Method string
	Path   string
	Query  string
	UA     string
	Addr   netip.Addr
	Loc    geoip.Location
	Body   []byte
	HTTP   *http.Request
}

// WAFInfo describes the WAF outcome for logging.
type WAFInfo struct {
	Matched bool
	RuleID  int
	Label   string
	Message string
	Profile string
}

type ruleSet struct {
	ipAllow      []netip.Prefix
	ipDeny       []netip.Prefix
	countryAllow map[string]bool
	countryDeny  map[string]bool
	asnDeny      map[int]bool
	decoys       []string
	rateRPS      int
	rateBurst    int

	// Per-host lists from the proxy's access profile. They stack on top of the
	// global lists: a profile deny always blocks, and a profile allow list
	// narrows that host to the addresses and countries it names.
	profIPAllow      []netip.Prefix
	profIPDeny       []netip.Prefix
	profCountryAllow map[string]bool
	profCountryDeny  map[string]bool
}

// Engine holds cached policies and the rate limiter.
type Engine struct {
	st    *store.Store
	bans  *ban.Engine
	feeds *intel.Manager
	geo   *geoip.Geo
	wafs  *waf.Set
	log   *slog.Logger
	rl    *limiter

	mu       sync.RWMutex
	global   ruleSet
	perProxy map[int64]ruleSet
	profiles map[int64]model.Profile
	settings Settings

	// An access profile is a named selection of policy rows with a role per
	// row. Keeping the rows themselves as the source of truth means editing a
	// policy updates every profile, and therefore every proxy, that uses it.
	accessProfiles map[int64]model.AccessProfile
	policiesByID   map[int64]model.Policy
	now            func() time.Time
}

// New builds an engine and loads the current configuration.
func New(st *store.Store, bans *ban.Engine, feeds *intel.Manager, geo *geoip.Geo, wafs *waf.Set, log *slog.Logger) (*Engine, error) {
	e := &Engine{
		st:             st,
		bans:           bans,
		feeds:          feeds,
		geo:            geo,
		wafs:           wafs,
		log:            log,
		rl:             newLimiter(),
		perProxy:       map[int64]ruleSet{},
		profiles:       map[int64]model.Profile{},
		accessProfiles: map[int64]model.AccessProfile{},
		policiesByID:   map[int64]model.Policy{},
		now:            time.Now,
	}
	if err := e.Reload(); err != nil {
		return nil, err
	}
	return e, nil
}

// DefaultHostingASNs is the curated cloud/VPS list blocked by default. The
// target users are residential/mobile, so this removes most commodity scanners
// before they reach the WAF. Operators can edit the list in settings.
var DefaultHostingASNs = []int{
	16509, 14618, // Amazon
	8075,          // Microsoft Azure
	15169, 396982, // Google / GCP
	14061,        // DigitalOcean
	63949,        // Linode / Akamai
	20473,        // Vultr
	16276,        // OVH
	24940,        // Hetzner
	51167,        // Contabo
	12876,        // Scaleway
	9009,         // M247
	26496,        // GoDaddy
	22612,        // Namecheap
	32244,        // Liquid Web
	36352,        // ColoCrossing
	54290,        // Hostwinds
	45102, 37963, // Alibaba Cloud
	132203, 45090, // Tencent Cloud
	53667, // FranTech
}

// DefaultDecoys are paths that no legitimate client of an ordinary web
// application requests. A decoy hit is an instant permanent ban, so the list
// deliberately excludes application paths such as /wp-login.php, /wp-admin,
// /xmlrpc.php, /phpmyadmin and /actuator: they are routine traffic for real
// WordPress, phpMyAdmin and Spring sites, and banning visitors for using them
// would lock out legitimate users. Add those per proxy with a decoy policy when
// a host never serves them.
var DefaultDecoys = []string{
	"/.env", "/.env.local", "/.env.production", "/.git/config", "/.svn/entries",
	"/.hg/hgrc", "/.aws/credentials", "/.htaccess", "/.htpasswd", "/.DS_Store",
	"/wp-config.php.bak", "/config.php.bak", "/backup.sql", "/dump.sql",
	"/database.sql", "/phpinfo.php", "/server-status",
}

// Reload refreshes policies, profiles and settings from the database.
func (e *Engine) Reload() error {
	policies, err := e.st.ListPolicies()
	if err != nil {
		return err
	}
	profiles, err := e.st.ListProfiles()
	if err != nil {
		return err
	}
	kv, err := e.st.Settings()
	if err != nil {
		return err
	}

	accessProfiles, err := e.st.ListAccessProfiles()
	if err != nil {
		return err
	}

	global := newRuleSet()
	perProxy := map[int64]ruleSet{}
	byID := map[int64]model.Policy{}
	for _, p := range policies {
		byID[p.ID] = p
		if !p.Enabled {
			continue
		}
		target := &global
		if p.Scope == "proxy" && p.ProxyID != nil {
			rs := perProxy[*p.ProxyID]
			if rs.countryAllow == nil {
				rs = newRuleSet()
			}
			target = &rs
			applyPolicy(target, p)
			perProxy[*p.ProxyID] = rs
			continue
		}
		applyPolicy(target, p)
	}
	if len(global.decoys) == 0 {
		global.decoys = append(global.decoys, DefaultDecoys...)
	}
	bundles := map[int64]model.AccessProfile{}
	for _, a := range accessProfiles {
		bundles[a.ID] = a
	}

	e.mu.Lock()
	e.global = global
	e.perProxy = perProxy
	e.profiles = map[int64]model.Profile{}
	for _, p := range profiles {
		e.profiles[p.ID] = p
	}
	e.accessProfiles = bundles
	e.policiesByID = byID
	e.settings = parseSettings(kv)
	e.mu.Unlock()
	return nil
}

func newRuleSet() ruleSet {
	return ruleSet{
		countryAllow:     map[string]bool{},
		countryDeny:      map[string]bool{},
		asnDeny:          map[int]bool{},
		profCountryAllow: map[string]bool{},
		profCountryDeny:  map[string]bool{},
	}
}

// applyPolicyRole applies one list to a rule set with the role the access
// profile chose. "inherit" falls back to the list's own kind, which is how
// profiles behaved before roles existed.
func applyPolicyRole(rs *ruleSet, p model.Policy, role string) {
	switch role {
	case model.AccessRoleAllow:
		switch p.Kind {
		case model.PolicyIPWhitelist, model.PolicyIPBlacklist:
			rs.profIPAllow = append(rs.profIPAllow, prefixes(p.Value)...)
		case model.PolicyCountryWhitelist, model.PolicyCountryBlacklist:
			for _, c := range splitUpper(p.Value) {
				rs.profCountryAllow[c] = true
			}
		}
	case model.AccessRoleDeny:
		switch p.Kind {
		case model.PolicyIPWhitelist, model.PolicyIPBlacklist:
			rs.profIPDeny = append(rs.profIPDeny, prefixes(p.Value)...)
		case model.PolicyCountryWhitelist, model.PolicyCountryBlacklist:
			for _, c := range splitUpper(p.Value) {
				rs.profCountryDeny[c] = true
			}
		}
	default:
		applyPolicy(rs, p)
	}
}

// prefixes parses a comma-separated IP/CIDR list, dropping anything malformed
// (the API rejects those on save).
func prefixes(value string) []netip.Prefix {
	out := []netip.Prefix{}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if pr, err := netmatchPrefix(part); err == nil {
			out = append(out, pr)
		}
	}
	return out
}

func applyPolicy(rs *ruleSet, p model.Policy) {
	switch p.Kind {
	case model.PolicyIPWhitelist:
		rs.ipAllow = append(rs.ipAllow, prefixes(p.Value)...)
	case model.PolicyIPBlacklist:
		rs.ipDeny = append(rs.ipDeny, prefixes(p.Value)...)
	case model.PolicyCountryWhitelist:
		for _, c := range splitUpper(p.Value) {
			rs.countryAllow[c] = true
		}
	case model.PolicyCountryBlacklist:
		for _, c := range splitUpper(p.Value) {
			rs.countryDeny[c] = true
		}
	case model.PolicyASNBlock:
		for _, n := range strings.Split(p.Value, ",") {
			if v, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
				rs.asnDeny[v] = true
			}
		}
	case model.PolicyDecoy:
		for _, entry := range strings.Split(p.Value, ",") {
			entry = canonicalPath(strings.TrimSpace(entry))
			if entry != "" {
				rs.decoys = append(rs.decoys, entry)
			}
		}
	case "rate_limit":
		parts := strings.Split(p.Value, "/")
		if len(parts) == 2 {
			if v, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil {
				rs.rateRPS = v
			}
			if v, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
				rs.rateBurst = v
			}
		}
	}
}

func netmatchPrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}

func splitUpper(s string) []string {
	out := []string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.ToUpper(strings.TrimSpace(part))
		if len(part) == 2 {
			out = append(out, part)
		}
	}
	return out
}

func parseSettings(kv map[string]string) Settings {
	s := Settings{
		RPS: 100, Burst: 200, ASNBlock: true, StealthDrop: true, StealthPing: false,
		RetentionDays: 7, SampleAboveRPS: 500, MaxBody: 131072, Enabled: true,
		WANIface: kv["wan_iface"],
		LANIface: kv["lan_iface"],
	}
	if v, err := strconv.Atoi(kv["dos_rps"]); err == nil && v > 0 {
		s.RPS = v
	}
	if v, err := strconv.Atoi(kv["dos_burst"]); err == nil && v > 0 {
		s.Burst = v
	}
	s.ASNBlock = kv["asn_block"] != "0"
	s.StealthDrop = kv["stealth_drop"] != "0"
	s.StealthPing = kv["stealth_ping"] == "1"
	s.Enabled = kv["protection_enabled"] != "0"
	s.DecoyHosts = parseDecoyHosts(kv["decoy_hosts"])
	if v, err := strconv.Atoi(kv["retention_days"]); err == nil && v >= 1 && v <= 30 {
		s.RetentionDays = v
	}
	if v, err := strconv.Atoi(kv["sample_above_rps"]); err == nil && v > 0 {
		s.SampleAboveRPS = v
	}
	if v, err := strconv.ParseInt(kv["max_body"], 10, 64); err == nil && v > 0 {
		s.MaxBody = v
	}
	return s
}

// NormalizeHost lowercases a hostname and removes a trailing dot, matching the
// normalization the proxy applies before routing.
func NormalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// ValidDecoyHost accepts a DNS label sequence. Single labels are allowed so an
// operator can trap scans for names like "admin" that never resolve publicly.
func ValidDecoyHost(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func parseDecoyHosts(raw string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		host := NormalizeHost(part)
		if ValidDecoyHost(host) {
			out[host] = true
		}
	}
	return out
}

// DecoyHost reports whether a hostname is configured as a decoy. It is checked
// before the unknown-host blackhole so a scan for these names is banned rather
// than silently dropped.
func (e *Engine) DecoyHost(host string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.settings.DecoyHosts[NormalizeHost(host)]
}

// CurrentSettings returns a copy of the cached settings.
func (e *Engine) CurrentSettings() Settings {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.settings
}

// ProfileAllowedMethods returns the methods permitted by a proxy's profile.
func (e *Engine) ProfileAllowedMethods(p *model.Proxy) map[string]bool {
	if p == nil || p.ProfileID == nil {
		return nil
	}
	e.mu.RLock()
	prof, ok := e.profiles[*p.ProfileID]
	e.mu.RUnlock()
	if !ok {
		return nil
	}
	out := map[string]bool{}
	for _, m := range strings.Split(prof.AllowedMethods, ",") {
		if m = strings.TrimSpace(strings.ToUpper(m)); m != "" {
			out[m] = true
		}
	}
	return out
}

// MaxBody returns the effective body inspection limit.
func (e *Engine) MaxBody(p *model.Proxy) int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if p != nil && p.ProfileID != nil {
		if prof, ok := e.profiles[*p.ProfileID]; ok && prof.MaxBody > 0 {
			return prof.MaxBody
		}
	}
	return e.settings.MaxBody
}

func (e *Engine) rulesFor(p *model.Proxy) ruleSet {
	e.mu.RLock()
	defer e.mu.RUnlock()
	merged := newRuleSet()
	merged.ipAllow = append(merged.ipAllow, e.global.ipAllow...)
	merged.ipDeny = append(merged.ipDeny, e.global.ipDeny...)
	for c := range e.global.countryAllow {
		merged.countryAllow[c] = true
	}
	for c := range e.global.countryDeny {
		merged.countryDeny[c] = true
	}
	for a := range e.global.asnDeny {
		merged.asnDeny[a] = true
	}
	merged.decoys = append(merged.decoys, e.global.decoys...)
	merged.rateRPS, merged.rateBurst = e.global.rateRPS, e.global.rateBurst
	if p != nil {
		if local, ok := e.perProxy[p.ID]; ok {
			merged.ipAllow = append(merged.ipAllow, local.ipAllow...)
			merged.ipDeny = append(merged.ipDeny, local.ipDeny...)
			for c := range local.countryAllow {
				merged.countryAllow[c] = true
			}
			for c := range local.countryDeny {
				merged.countryDeny[c] = true
			}
			for a := range local.asnDeny {
				merged.asnDeny[a] = true
			}
			merged.decoys = append(merged.decoys, local.decoys...)
			if local.rateRPS > 0 {
				merged.rateRPS = local.rateRPS
			}
			if local.rateBurst > 0 {
				merged.rateBurst = local.rateBurst
			}
		}
		// A profile adds its lists to this proxy only, each with the role the
		// profile gives it. Disabled lists are skipped, so turning a list off in
		// Policies also turns it off here.
		if p.AccessProfileID != nil {
			if prof, ok := e.accessProfiles[*p.AccessProfileID]; ok {
				for _, rule := range prof.Rules {
					if pol, ok := e.policiesByID[rule.PolicyID]; ok && pol.Enabled {
						applyPolicyRole(&merged, pol, rule.Role)
					}
				}
			}
		}
	}
	return merged
}

// Screen runs every stage before the access gate and WAF.
func (e *Engine) Screen(req *Request) model.Verdict {
	p := req.Proxy
	rules := e.rulesFor(p)
	country := ""
	if req.Loc.Country != "" {
		country = strings.ToUpper(req.Loc.Country)
	}

	// A permanent ban is absolute: no whitelist can override it.
	if rec, ok := e.bans.Match(req.Addr); ok && rec.Permanent {
		e.bans.NoteHit(req.Addr)
		return model.Verdict{Action: "ban", Stage: "permanent-ban", Rule: rec.CIDR,
			Reason: rec.Reason, Status: http.StatusForbidden, BanSource: rec.Source}
	}

	// A permanent ban rolled into a local threat list keeps its absolute force:
	// it is checked before the allow lists, so a whitelist cannot lift it.
	if e.feeds != nil {
		if entry, ok := e.feeds.MatchAlways(req.Addr); ok {
			return model.Verdict{Action: "block", Stage: "permanent-ban-list", Rule: entry.Feed,
				Reason: "address is on a permanent ban list", Status: http.StatusForbidden}
		}
	}

	// An explicit IP block list beats the allow list: a compromised allowlisted
	// host is still refused, which is what an operator means by "block this IP".
	for _, pr := range rules.ipDeny {
		if pr.Contains(req.Addr) {
			return model.Verdict{Action: "block", Stage: "ip-blacklist", Rule: pr.String(),
				Reason: "IP on the block list", Status: http.StatusForbidden}
		}
	}

	// A profile deny list drops the address for this host even when a global
	// allow list names it: an explicit block is the operator's strongest word.
	for _, pr := range rules.profIPDeny {
		if pr.Contains(req.Addr) {
			return model.Verdict{Action: "block", Stage: "profile-block", Rule: pr.String(),
				Reason: "IP blocked by this site's access profile", Status: http.StatusForbidden}
		}
	}
	if country != "" && rules.profCountryDeny[country] {
		return model.Verdict{Action: "block", Stage: "profile-block", Rule: "country:" + country,
			Reason: "country blocked by this site's access profile", Status: http.StatusForbidden}
	}

	// A whitelist only bypasses the country, ASN and feed stages. Bans,
	// decoys and rate limiting still apply, so a compromised friendly host
	// cannot use its whitelist entry to escape the IPS.
	allowlisted := false
	allowRule := ""
	for _, pr := range rules.ipAllow {
		if pr.Contains(req.Addr) {
			allowlisted = true
			allowRule = pr.String()
			break
		}
	}
	if !allowlisted && country != "" && rules.countryAllow[country] {
		allowlisted = true
		allowRule = "country:" + country
	}
	// An allow list is exclusive: once it names any country, traffic from
	// everywhere else is refused. An IP whitelist still wins above. With no
	// country data the allow list fails closed rather than silently opening
	// the site; the UI already reports GeoIP as unavailable in that case.
	if !allowlisted && len(rules.countryAllow) > 0 {
		rule := "country:" + country
		if country == "" {
			rule = "country:unknown"
		}
		return model.Verdict{Action: "block", Stage: "country-allow", Rule: rule,
			Reason: "country not on the allow list", Status: http.StatusForbidden}
	}

	// The profile's own allow list is exclusive for this host: once a site names
	// the addresses or countries allowed to reach it, nothing else does. This is
	// what makes a per-host profile more granular than the global setting.
	if len(rules.profIPAllow) > 0 || len(rules.profCountryAllow) > 0 {
		ok := country != "" && rules.profCountryAllow[country]
		if !ok {
			for _, pr := range rules.profIPAllow {
				if pr.Contains(req.Addr) {
					ok = true
					break
				}
			}
		}
		if !ok {
			rule := "country:" + country
			if country == "" {
				rule = "country:unknown"
			}
			return model.Verdict{Action: "block", Stage: "profile-allow", Rule: rule,
				Reason: "address not on this site's access profile", Status: http.StatusForbidden}
		}
	}

	// A decoy path is proof of scanning, and a whitelisted host is exactly the
	// one worth watching: a whitelist exempts country, ASN and feed policy, not
	// the honeypot. The path is canonicalised first because "/./.env", "//.env"
	// and "/x/../.env" all reach the same file on a typical upstream.
	lowerPath := canonicalPath(req.Path)
	for _, decoy := range rules.decoys {
		if lowerPath == decoy || strings.HasPrefix(lowerPath, decoy+"/") {
			rawPath := req.Path
			addr := req.Addr.String()
			go func() {
				_, _ = e.bans.Add(addr, "decoy path requested: "+rawPath, "decoy", "policy", 0)
			}()
			return model.Verdict{Action: "ban", Stage: "decoy", Rule: decoy,
				Reason: "decoy path", Status: http.StatusForbidden, BanSource: "decoy"}
		}
	}

	if !allowlisted {
		if country != "" && rules.countryDeny[country] {
			return model.Verdict{Action: "block", Stage: "country-block", Rule: "country:" + country,
				Reason: "country not permitted", Status: http.StatusForbidden}
		}
		if req.Loc.ASN > 0 {
			e.mu.RLock()
			asnBlock := e.settings.ASNBlock
			e.mu.RUnlock()
			if (asnBlock || len(rules.asnDeny) > 0) && (rules.asnDeny[req.Loc.ASN] || (asnBlock && isHostingASN(req.Loc.ASN))) {
				return model.Verdict{Action: "block", Stage: "asn-block", Rule: "asn:" + strconv.Itoa(req.Loc.ASN),
					Reason: "hosting/cloud network not permitted", Status: http.StatusForbidden}
			}
		}

		if e.feeds != nil {
			if entry, ok := e.feeds.Match(req.Addr); ok {
				switch entry.Action {
				case "log":
					return model.Verdict{Action: "log", Stage: "feed", Rule: entry.Feed, Reason: "feed match", Status: http.StatusOK}
				case "challenge":
					return model.Verdict{Action: "challenge", Stage: "feed", Rule: entry.Feed, Reason: "feed match", Status: http.StatusForbidden}
				default:
					return model.Verdict{Action: "block", Stage: "feed", Rule: entry.Feed, Reason: "listed in threat feed", Status: http.StatusForbidden}
				}
			}
		}
	}

	if rec, ok := e.bans.Match(req.Addr); ok {
		e.bans.NoteHit(req.Addr)
		return model.Verdict{Action: "ban", Stage: "temp-ban", Rule: rec.CIDR,
			Reason: rec.Reason, Status: http.StatusForbidden, BanSource: rec.Source}
	}

	prof := e.ProfileFor(p)
	// An admin path is meant for the operator's own network: the profile names
	// the addresses allowed to reach it, and everyone else gets the same uniform
	// rejection the rest of the pipeline uses.
	if prof != nil && strings.TrimSpace(prof.AdminIPs) != "" && pathUnderAny(req.Path, prof.AdminPaths) {
		if !addrInPrefixes(req.Addr, prof.AdminIPs) {
			return model.Verdict{Action: "block", Stage: "admin-path", Rule: canonicalPath(req.Path),
				Reason: "admin path is not reachable from this address", Status: http.StatusForbidden}
		}
	}

	e.mu.RLock()
	dosRPS, dosBurst := e.settings.RPS, e.settings.Burst
	e.mu.RUnlock()
	if rules.rateRPS > 0 {
		dosRPS = rules.rateRPS
	}
	if rules.rateBurst > 0 {
		dosBurst = rules.rateBurst
	}
	if allowed, strikeOut := e.rl.Allow(rateKey(req), dosRPS, dosBurst, e.now()); !allowed {
		if strikeOut {
			addr := req.Addr.String()
			go func() {
				_, _ = e.bans.Add(addr, "request rate exceeded", "scan", "ratelimit", 60*time.Second)
			}()
		}
		return model.Verdict{Action: "block", Stage: "dos", Rule: "rate-limit",
			Reason: "request rate exceeded", Status: http.StatusTooManyRequests}
	}

	// Credential stuffing is throttled per client and per login path before the
	// request reaches an application that may have no limit of its own.
	if prof != nil && prof.LoginRPS > 0 && pathUnderAny(req.Path, prof.LoginPaths) {
		burst := prof.LoginBurst
		if burst <= 0 {
			burst = prof.LoginRPS
		}
		key := "login|" + rateKey(req) + "|" + canonicalPath(req.Path)
		if allowed, _ := e.rl.Allow(key, prof.LoginRPS, burst, e.now()); !allowed {
			return model.Verdict{Action: "block", Stage: "login-limit", Rule: "rate-limit",
				Reason: "login attempts exceeded", Status: http.StatusTooManyRequests}
		}
	}

	if req.Method == http.MethodTrace {
		return model.Verdict{Action: "block", Stage: "protocol", Rule: "trace",
			Reason: "TRACE is disabled", Status: http.StatusMethodNotAllowed}
	}
	if allowed := e.ProfileAllowedMethods(p); len(allowed) > 0 && !allowed[req.Method] {
		return model.Verdict{Action: "block", Stage: "method", Rule: req.Method,
			Reason: "method not allowed by profile", Status: http.StatusMethodNotAllowed}
	}
	if allowlisted {
		return model.Verdict{Action: "allow", Stage: "whitelist", Rule: allowRule, Status: http.StatusOK}
	}
	return model.Verdict{Action: "allow", Stage: "route", Status: http.StatusOK}
}

// Start runs periodic limiter housekeeping so spoofed source addresses cannot
// grow the rate-limit table without bound.
func (e *Engine) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				e.rl.Cleanup()
			}
		}
	}()
}

// ReloadWAF recompiles the protection profiles after an edit.
func (e *Engine) ReloadWAF() error {
	profiles, err := e.st.ListProfiles()
	if err != nil {
		return err
	}
	e.wafs.Reload(profiles)
	e.mu.Lock()
	e.profiles = map[int64]model.Profile{}
	for _, p := range profiles {
		e.profiles[p.ID] = p
	}
	e.mu.Unlock()
	return nil
}

// ProfileFor returns the WAF profile a proxy selects. The proxy edge keeps its
// own copy of the values it enforces on responses, so a reload replaces both.
func (e *Engine) ProfileFor(p *model.Proxy) *model.Profile {
	if p == nil || p.ProfileID == nil {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	prof, ok := e.profiles[*p.ProfileID]
	if !ok {
		return nil
	}
	return &prof
}

// pathUnderAny reports whether a path is one of the listed prefixes or below
// one. An empty list matches nothing.
func pathUnderAny(p, list string) bool {
	clean := canonicalPath(p)
	for _, prefix := range strings.Split(list, ",") {
		prefix = strings.ToLower(strings.TrimSpace(prefix))
		if prefix == "" {
			continue
		}
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		prefix = strings.TrimSuffix(prefix, "/")
		if prefix == "" || clean == prefix || strings.HasPrefix(clean, prefix+"/") {
			return true
		}
	}
	return false
}

// addrInPrefixes reports whether an address is inside any listed prefix. The
// API rejects malformed entries on save; one left in the row by hand matches
// nothing, so the rule fails closed rather than admitting everyone.
func addrInPrefixes(addr netip.Addr, list string) bool {
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pr, err := netmatchPrefix(part)
		if err != nil {
			continue
		}
		if pr.Contains(addr) {
			return true
		}
	}
	return false
}

// canonicalPath resolves dot segments, duplicate slashes and case the way most
// upstreams do before they route, so a path-based rule cannot be sidestepped
// with "/./x", "//x" or "/y/../x". The request keeps its original path: only
// the comparison uses the canonical form.
func canonicalPath(p string) string {
	if p == "" {
		return "/"
	}
	return strings.ToLower(path.Clean("/" + p))
}

func rateKey(req *Request) string {
	id := int64(0)
	if req.Proxy != nil {
		id = req.Proxy.ID
	}
	return req.Addr.String() + "|" + strconv.FormatInt(id, 10)
}

func isHostingASN(asn int) bool {
	if _, ok := hostingASN[asn]; ok {
		return true
	}
	return false
}

var hostingASN = func() map[int]bool {
	m := map[int]bool{}
	for _, a := range DefaultHostingASNs {
		m[a] = true
	}
	return m
}()

// Inspect runs the WAF stage for a request whose body has already been read.
func (e *Engine) Inspect(req *Request) (model.Verdict, WAFInfo) {
	p := req.Proxy
	if p == nil {
		return model.Verdict{Action: "allow", Stage: "waf"}, WAFInfo{}
	}
	mode := p.WAFMode
	if mode == "" || mode == "inherit" {
		e.mu.RLock()
		mode = "block"
		if p.ProfileID != nil {
			if prof, ok := e.profiles[*p.ProfileID]; ok && prof.Mode != "" {
				mode = prof.Mode
			}
		}
		e.mu.RUnlock()
	}
	if mode == "off" {
		return model.Verdict{Action: "allow", Stage: "waf"}, WAFInfo{}
	}
	engine := e.wafs.For(p.ProfileID)
	if engine == nil {
		return model.Verdict{Action: "allow", Stage: "waf"}, WAFInfo{}
	}
	res := engine.Inspect(req.HTTP, req.Body, req.Addr)
	info := WAFInfo{Matched: res.Matched, RuleID: res.RuleID, Label: res.Label, Message: res.Message, Profile: engine.Name()}
	if !res.Matched {
		return model.Verdict{Action: "allow", Stage: "waf"}, info
	}
	if mode == "detect" || !res.Blocked {
		return model.Verdict{Action: "log", Stage: "waf", Rule: strconv.Itoa(res.RuleID),
			Reason: res.Message, Status: http.StatusOK}, info
	}
	return model.Verdict{Action: "block", Stage: "waf", Rule: strconv.Itoa(res.RuleID),
		Reason: res.Label + ": " + res.Message, Status: http.StatusForbidden}, info
}

// NoteTraffic records request volume for sampling decisions.
func (e *Engine) NoteTraffic() { e.rl.noteTraffic() }

// ShouldSample reports whether an allowed request may be downsampled.
func (e *Engine) ShouldSample() bool {
	e.mu.RLock()
	limit := e.settings.SampleAboveRPS
	e.mu.RUnlock()
	return e.rl.shouldSample(limit)
}
