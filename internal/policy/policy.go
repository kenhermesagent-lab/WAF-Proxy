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
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/norm"
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
	// BotFilter refuses whole categories of automation; the proof-of-work
	// challenge is separate and still applies to the traffic it lets through.
	BotFilter      string
	BotFilterAllow string
	DecoyHosts     map[string]bool
	// NormalizationMode is off, flag or block. It only applies while the WAF
	// stage itself is running.
	NormalizationMode string
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
	// BodyStreamed says the body is forwarded unread, as on a body-skip path.
	// The WAF then drops its content-type and method policy rules, which would
	// refuse a raw upload before the exemption could apply.
	BodyStreamed bool
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

	// The named lists behind those entries, so a verdict can name the list that
	// matched. Values are list names keyed by canonical prefix or country code.
	listIPDeny       map[string]string
	listIPAllow      map[string]string
	listCountryDeny  map[string]string
	listCountryAllow map[string]string
	listAllowNames   []string

	// Named lists attached under Policies → Global Profile. A whitelist is
	// checked before every block list; a blocklist applies to every host.
	globalAllowIP     []netip.Prefix
	globalAllowC      map[string]bool
	globalAllowIPName map[string]string
	globalAllowCName  map[string]string
	globalAllowNames  []string
	globalDenyIP      []netip.Prefix
	globalDenyC       map[string]bool
	globalDenyIPName  map[string]string
	globalDenyCName   map[string]string
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

	mu         sync.RWMutex
	global     ruleSet
	perProxy   map[int64]ruleSet
	profiles   map[int64]model.Profile
	settings   Settings
	siteByHost map[string]int64
	// bundleRules supplies the installed signature packs whenever an engine
	// is recompiled. It is a function so the manager can swap packs without
	// the policy layer holding a reference to it.
	bundleRules func() []waf.Bundle

	// An access profile is a named selection of policy rows with a role per
	// row. Keeping the rows themselves as the source of truth means editing a
	// policy updates every profile, and therefore every proxy, that uses it.
	accessProfiles map[int64]model.AccessProfile
	policiesByID   map[int64]model.Policy

	// Named block/allow lists, compiled at reload so a request merges prefixes
	// instead of parsing them.
	lists map[int64]compiledList
	now   func() time.Time
}

// compiledList is one named blocklist or whitelist: a blocklist denies every
// entry it holds, a whitelist makes the site reachable only from them.
type compiledList struct {
	name      string
	block     bool
	ips       []netip.Prefix
	countries map[string]bool
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
		lists:          map[int64]compiledList{},
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
	proxies, err := e.st.ListProxies()
	if err != nil {
		return err
	}
	siteByHost := make(map[string]int64, len(proxies))
	for _, p := range proxies {
		siteByHost[p.Hostname] = p.SiteID
	}

	accessProfiles, err := e.st.ListAccessProfiles()
	if err != nil {
		return err
	}
	lists, err := e.st.ListAccessLists()
	if err != nil {
		return err
	}
	compiled := map[int64]compiledList{}
	for _, l := range lists {
		cl := compiledList{name: l.Name, block: l.Kind == model.ListKindBlock, ips: prefixes(l.IPs), countries: map[string]bool{}}
		for _, c := range splitUpper(l.Countries) {
			cl.countries[c] = true
		}
		compiled[l.ID] = cl
	}

	global := newRuleSet()
	// A named list checked as global applies to every host. The whitelist is
	// merged first and evaluated first, so the console's order (allow above
	// block) is the order the engine uses.
	for _, id := range settingIDs(kv["global_whitelist_ids"]) {
		l, ok := compiled[id]
		if !ok || l.block {
			continue
		}
		for _, pr := range l.ips {
			global.globalAllowIP = append(global.globalAllowIP, pr)
			global.globalAllowIPName[pr.String()] = l.name
		}
		for c := range l.countries {
			global.globalAllowC[c] = true
			global.globalAllowCName[c] = l.name
		}
		global.globalAllowNames = append(global.globalAllowNames, l.name)
	}
	for _, id := range settingIDs(kv["global_blocklist_ids"]) {
		l, ok := compiled[id]
		if !ok || !l.block {
			continue
		}
		for _, pr := range l.ips {
			global.globalDenyIP = append(global.globalDenyIP, pr)
			global.globalDenyIPName[pr.String()] = l.name
		}
		for c := range l.countries {
			global.globalDenyC[c] = true
			global.globalDenyCName[c] = l.name
		}
	}
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
	e.lists = compiled
	e.siteByHost = siteByHost
	e.settings = parseSettings(kv)
	e.mu.Unlock()
	return nil
}

func newRuleSet() ruleSet {
	return ruleSet{
		countryAllow:      map[string]bool{},
		countryDeny:       map[string]bool{},
		asnDeny:           map[int]bool{},
		profCountryAllow:  map[string]bool{},
		profCountryDeny:   map[string]bool{},
		listIPDeny:        map[string]string{},
		listIPAllow:       map[string]string{},
		listCountryDeny:   map[string]string{},
		listCountryAllow:  map[string]string{},
		globalAllowC:      map[string]bool{},
		globalAllowIPName: map[string]string{},
		globalAllowCName:  map[string]string{},
		globalDenyC:       map[string]bool{},
		globalDenyIPName:  map[string]string{},
		globalDenyCName:   map[string]string{},
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
		RetentionDays: 7, SampleAboveRPS: 500, MaxBody: model.DefaultMaxBody, Enabled: true,
		WANIface:          kv["wan_iface"],
		LANIface:          kv["lan_iface"],
		NormalizationMode: normalizationMode(kv["normalization_mode"]),
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
	s.BotFilter = defaultBotMode(kv["bot_filter"])
	s.BotFilterAllow = kv["bot_filter_allow"]
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

// normalizationMode defaults to flag: a new check must be visible in the event
// log before an operator turns it into a block.
func normalizationMode(mode string) string {
	switch mode {
	case "off", "flag", "block":
		return mode
	}
	return "flag"
}

func defaultBotMode(mode string) string {
	switch mode {
	case "scrapers", "all":
		return mode
	case "off":
		return mode
	}
	// An unset value is off: enabling a user-agent block must be a decision, so
	// an upgraded install never starts refusing crawlers on its own.
	return "off"
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

// siteFor maps a hostname to the site that owns it, so a ban raised while
// serving that host is recorded on the site whose console will list it.
func (e *Engine) siteFor(host string) int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.siteByHost[NormalizeHost(host)]
}

// ResponseEngine is the compiled profile the proxy's responses are inspected
// with. A per-site engine holds only its own site's profiles, so the lookup
// cannot reach another site's row.
func (e *Engine) ResponseEngine(p *model.Proxy) *waf.Engine {
	if p == nil {
		return nil
	}
	return e.WAFEngine(p.ProfileID)
}

// Settings returns the cached settings of the site this engine was built for.
// A per-site engine ignores the id: it already reads one site's rows.
func (e *Engine) Settings(siteID int64) Settings { return e.CurrentSettings() }

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
	// Global named lists are read-only after Reload, so every host can share
	// them instead of copying the entries on each request.
	merged.globalAllowIP = e.global.globalAllowIP
	merged.globalAllowC = e.global.globalAllowC
	merged.globalAllowIPName = e.global.globalAllowIPName
	merged.globalAllowCName = e.global.globalAllowCName
	merged.globalAllowNames = e.global.globalAllowNames
	merged.globalDenyIP = e.global.globalDenyIP
	merged.globalDenyC = e.global.globalDenyC
	merged.globalDenyIPName = e.global.globalDenyIPName
	merged.globalDenyCName = e.global.globalDenyCName
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
				// A named blocklist is the operator's block for this host, and a
				// whitelist narrows it to what it names, exactly as a deny/allow
				// rule on a policy does.
				for _, id := range prof.ListIDs {
					l, ok := e.lists[id]
					if !ok {
						continue
					}
					if l.block {
						for _, pr := range l.ips {
							merged.profIPDeny = append(merged.profIPDeny, pr)
							merged.listIPDeny[pr.String()] = l.name
						}
						for c := range l.countries {
							merged.profCountryDeny[c] = true
							merged.listCountryDeny[c] = l.name
						}
						continue
					}
					merged.listAllowNames = append(merged.listAllowNames, l.name)
					for _, pr := range l.ips {
						merged.profIPAllow = append(merged.profIPAllow, pr)
						merged.listIPAllow[pr.String()] = l.name
					}
					for c := range l.countries {
						merged.profCountryAllow[c] = true
						merged.listCountryAllow[c] = l.name
					}
				}
			}
		}
	}
	return merged
}

// Screen runs every stage before the access gate and WAF.
func (e *Engine) Screen(req *Request) model.Verdict {
	return e.screen(req, true)
}

// screen is Screen with its stateful stages switchable off: a simulation must
// not spend a client's rate budget or write a ban for a request nobody sent.
func (e *Engine) screen(req *Request, live bool) model.Verdict {
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

	// A global whitelist is the operator's strongest allow: it is checked before
	// the global blocklist, the per-site lists, and the country, ASN and feed
	// stages. Decoys, bans, rate limits and the WAF still apply, so a trusted
	// host that scans is still caught.
	allowlisted := false
	allowRule, allowListName := "", ""
	if name, rule, ok := matchGlobalList(rules.globalAllowIP, rules.globalAllowIPName, rules.globalAllowC, rules.globalAllowCName, req.Addr, country); ok {
		allowlisted, allowRule, allowListName = true, rule, name
	} else if name, rule, ok := matchGlobalList(rules.globalDenyIP, rules.globalDenyIPName, rules.globalDenyC, rules.globalDenyCName, req.Addr, country); ok {
		return model.Verdict{Action: "block", Stage: "global-list", Rule: rule, List: name,
			Reason: "address is on the global blocklist \"" + name + "\"", Status: http.StatusForbidden}
	}

	// An explicit IP block list beats the allow list: a compromised allowlisted
	// host is still refused, which is what an operator means by "block this IP".
	if !allowlisted {
		for _, pr := range rules.ipDeny {
			if pr.Contains(req.Addr) {
				return model.Verdict{Action: "block", Stage: "ip-blacklist", Rule: pr.String(),
					Reason: "IP on the block list", Status: http.StatusForbidden}
			}
		}
	}

	// A profile deny list drops the address for this host even when a global
	// allow list names it: an explicit block is the operator's strongest word.
	// A per-site list is narrower than the global one, so it still decides for
	// its own host: a global whitelist does not lift a site's blocklist.
	for _, pr := range rules.profIPDeny {
		if pr.Contains(req.Addr) {
			if name, ok := rules.listIPDeny[pr.String()]; ok {
				return model.Verdict{Action: "block", Stage: "list-block", Rule: pr.String(), List: name,
					Reason: "address is on the \"" + name + "\" blocklist", Status: http.StatusForbidden}
			}
			return model.Verdict{Action: "block", Stage: "profile-block", Rule: pr.String(),
				Reason: "IP blocked by this site's access profile", Status: http.StatusForbidden}
		}
	}
	if country != "" && rules.profCountryDeny[country] {
		if name, ok := rules.listCountryDeny[country]; ok {
			return model.Verdict{Action: "block", Stage: "list-block", Rule: "country:" + country, List: name,
				Reason: "country " + country + " is on the \"" + name + "\" blocklist", Status: http.StatusForbidden}
		}
		return model.Verdict{Action: "block", Stage: "profile-block", Rule: "country:" + country,
			Reason: "country blocked by this site's access profile", Status: http.StatusForbidden}
	}

	// A whitelist only bypasses the country, ASN and feed stages. Bans,
	// decoys and rate limiting still apply, so a compromised friendly host
	// cannot use its whitelist entry to escape the IPS.
	// The profile allow lists are checked further down; a match from a named
	// whitelist is reported as such, after the stages that still apply.
	profileAllowRule, profileAllowList := "", ""
	if !allowlisted {
		for _, pr := range rules.ipAllow {
			if pr.Contains(req.Addr) {
				allowlisted = true
				allowRule = pr.String()
				break
			}
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
		ok := false
		matchedRule, matchedList := "", ""
		if country != "" {
			if name, hit := rules.listCountryAllow[country]; hit {
				ok, matchedList, matchedRule = true, name, "country:"+country
			}
		}
		for _, pr := range rules.profIPAllow {
			if ok {
				break
			}
			if pr.Contains(req.Addr) {
				ok, matchedRule = true, pr.String()
				matchedList = rules.listIPAllow[pr.String()]
			}
		}
		if !ok {
			rule := "country:" + country
			if country == "" {
				rule = "country:unknown"
			}
			if len(rules.listAllowNames) > 0 {
				return model.Verdict{Action: "block", Stage: "list-allow", Rule: rule,
					List: strings.Join(rules.listAllowNames, ", "), Reason: whitelistReason(rules.listAllowNames),
					Status: http.StatusForbidden}
			}
			return model.Verdict{Action: "block", Stage: "profile-allow", Rule: rule,
				Reason: "address not on this site's access profile", Status: http.StatusForbidden}
		}
		profileAllowRule, profileAllowList = matchedRule, matchedList
	}

	// A decoy path is proof of scanning, and a whitelisted host is exactly the
	// one worth watching: a whitelist exempts country, ASN and feed policy, not
	// the honeypot. The path is canonicalised first because "/./.env", "//.env"
	// and "/x/../.env" all reach the same file on a typical upstream.
	lowerPath := canonicalPath(req.Path)
	for _, decoy := range rules.decoys {
		if lowerPath == decoy || strings.HasPrefix(lowerPath, decoy+"/") {
			if live {
				rawPath := req.Path
				addr := req.Addr.String()
				site := e.siteFor(req.Host)
				go func() {
					_, _ = e.bans.AddFor(site, addr, "decoy path requested: "+rawPath, "decoy", "policy", 0)
				}()
			}
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
	if live {
		if allowed, strikeOut := e.rl.Allow(rateKey(req), dosRPS, dosBurst, e.now()); !allowed {
			if strikeOut {
				addr := req.Addr.String()
				site := e.siteFor(req.Host)
				go func() {
					_, _ = e.bans.AddFor(site, addr, "request rate exceeded", "scan", "ratelimit", 60*time.Second)
				}()
			}
			return model.Verdict{Action: "block", Stage: "dos", Rule: "rate-limit",
				Reason: "request rate exceeded", Status: http.StatusTooManyRequests}
		}

		// Credential stuffing is throttled per client and per login path before
		// the request reaches an application that may have no limit of its own.
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
	}

	if req.Method == http.MethodTrace {
		return model.Verdict{Action: "block", Stage: "protocol", Rule: "trace",
			Reason: "TRACE is disabled", Status: http.StatusMethodNotAllowed}
	}
	if allowed := e.ProfileAllowedMethods(p); len(allowed) > 0 && !allowed[req.Method] {
		return model.Verdict{Action: "block", Stage: "method", Rule: req.Method,
			Reason: "method not allowed by profile", Status: http.StatusMethodNotAllowed}
	}
	if profileAllowList != "" {
		return model.Verdict{Action: "allow", Stage: "list-allow", Rule: profileAllowRule, List: profileAllowList,
			Status: http.StatusOK}
	}
	if allowListName != "" {
		return model.Verdict{Action: "allow", Stage: "global-list", Rule: allowRule, List: allowListName,
			Status: http.StatusOK}
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

// SetBundleRules registers the installed signature packs. It must be called
// before the first ReloadWAF so a profile compiles with the packs on disk.
func (e *Engine) SetBundleRules(rules func() []waf.Bundle) {
	e.bundleRules = rules
}

// ReloadWAF recompiles the protection profiles after an edit.
func (e *Engine) ReloadWAF() error {
	profiles, err := e.st.ListProfiles()
	if err != nil {
		return err
	}
	// SetBundles drops the compiled engines, so it has to run before Reload
	// repopulates the profile configs.
	if e.bundleRules != nil {
		e.wafs.SetBundles(e.bundleRules())
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
// WAFEngine returns the compiled rules for a proxy's profile, so the response
// inspector applies the same exceptions and paranoia as the request path.
func (e *Engine) WAFEngine(profileID *int64) *waf.Engine {
	return e.wafs.For(profileID)
}

// ResponseInspection reports how a proxy's profile wants upstream responses
// handled: the response setting and the WAF mode that decides whether a match
// blocks or only logs. Both are read live, so saving a profile needs no proxy
// reload.
func (e *Engine) ResponseInspection(p *model.Proxy) (responses, mode string) {
	prof := e.ProfileFor(p)
	if prof == nil {
		return "off", ""
	}
	return prof.Responses, prof.Mode
}

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

// matchGlobalList reports the last list and rule a global whitelist or
// blocklist matched.
func matchGlobalList(ips []netip.Prefix, ipNames map[string]string, countries map[string]bool, countryNames map[string]string, addr netip.Addr, country string) (string, string, bool) {
	for _, pr := range ips {
		if pr.Contains(addr) {
			return ipNames[pr.String()], pr.String(), true
		}
	}
	if country != "" && countries[country] {
		return countryNames[country], "country:" + country, true
	}
	return "", "", false
}

// settingIDs parses the comma-separated list IDs a global profile setting
// holds. An unreadable entry is ignored rather than failing the whole reload.
func settingIDs(raw string) []int64 {
	out := []int64{}
	for _, part := range strings.Split(raw, ",") {
		if id, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// whitelistReason explains a refusal caused by the site's own whitelists. One
// list is named directly; with several, all of them are listed because the
// address has to be added to one of them.
func whitelistReason(names []string) string {
	if len(names) == 1 {
		return "address is not on the \"" + names[0] + "\" whitelist"
	}
	return "address is on none of the site's whitelists (" + strings.Join(names, ", ") + ")"
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
	verdict, info, _ := e.inspect(req)
	return verdict, info
}

// inspect is Inspect with the full rule list the simulator reports.
func (e *Engine) inspect(req *Request) (model.Verdict, WAFInfo, []waf.Match) {
	p := req.Proxy
	if p == nil {
		return model.Verdict{Action: "allow", Stage: "waf"}, WAFInfo{}, nil
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
		return model.Verdict{Action: "allow", Stage: "waf"}, WAFInfo{}, nil
	}
	// Fail closed. Without an engine the request cannot be judged, and an allow
	// here would be a WAF silently off for every request it could not compile.
	var engine *waf.Engine
	if e.wafs != nil {
		engine = e.wafs.For(p.ProfileID)
	}
	if engine == nil {
		return model.Verdict{Action: "block", Stage: "waf", Rule: "200010", Status: http.StatusServiceUnavailable,
			Reason: "no WAF engine is compiled for this profile"}, WAFInfo{}, nil
	}
	res, matches := engine.InspectAllWith(req.HTTP, req.Body, req.Addr, waf.InspectOptions{BodyStreamed: req.BodyStreamed})
	info := WAFInfo{Matched: res.Matched, RuleID: res.RuleID, Label: res.Label, Message: res.Message, Profile: engine.Name()}
	// RuleID 0 means the only matches were setup actions, so the rule set has
	// no verdict of its own. Normalization only speaks in that case, which also
	// keeps it from ever downgrading a real CRS block.
	if !res.Matched || res.RuleID == 0 {
		if v, ok := e.normVerdict(res.Norm); ok {
			info.Matched, info.Label, info.Message = true, "normalization", v.Reason
			info.RuleID, _ = strconv.Atoi(v.Rule)
			return v, info, matches
		}
		if !res.Matched {
			return model.Verdict{Action: "allow", Stage: "waf"}, info, matches
		}
	}
	// A CRS interruption is decided by the profile mode alone.
	if res.Blocked {
		rule, msg := res.RuleID, res.Message
		if id, m, ok := bestCRSMatch(matches); ok {
			rule, msg = id, m
		}
		if mode == "detect" {
			return model.Verdict{Action: "log", Stage: "waf", Rule: strconv.Itoa(rule),
				Reason: msg, Status: http.StatusOK}, info, matches
		}
		return model.Verdict{Action: "block", Stage: "waf", Rule: strconv.Itoa(rule),
			Reason: waf.Label(rule) + ": " + msg, Status: http.StatusForbidden}, info, matches
	}
	// A bundle rule resolves by its own per-profile switch: off is filtered at
	// compile time, log records, block refuses. CRS coverage is untouched by
	// whichever way this goes.
	if bm, ok := e.bestBundleMatch(matches, p); ok {
		info.Matched = true
		info.RuleID = bm.RuleID
		info.Message = bm.Message
		info.Label = "bundle"
		// A site pinned to detect-only keeps that promise even when its profile
		// allows the bundle to block: the per-site setting is the narrower one.
		if e.bundleMode(p, bm.Bundle) == model.BundleBlock && mode != "detect" {
			return model.Verdict{Action: "block", Stage: "waf", Rule: strconv.Itoa(bm.RuleID),
				Reason: "bundle " + bm.Bundle + ": " + bm.Message, Status: http.StatusForbidden}, info, matches
		}
		return model.Verdict{Action: "log", Stage: "waf", Rule: strconv.Itoa(bm.RuleID),
			Reason: bm.Message, Status: http.StatusOK}, info, matches
	}
	return model.Verdict{Action: "log", Stage: "waf", Rule: strconv.Itoa(res.RuleID),
		Reason: res.Message, Status: http.StatusOK}, info, matches
}

// bestCRSMatch names the CRS rule a block should be attributed to. A bundle
// rule can carry a higher severity than the CRS rule that interrupted, so the
// reported rule must be chosen by origin rather than by the lowest number.
func bestCRSMatch(matches []waf.Match) (int, string, bool) {
	best, msg, ok := 0, "", false
	severity := 999
	for _, m := range matches {
		if m.Origin == "bundle" {
			continue
		}
		if m.Severity < severity {
			best, msg, severity, ok = m.RuleID, m.Message, m.Severity, true
		}
	}
	return best, msg, ok
}

// bestBundleMatch picks the most severe bundle rule whose mode is not off.
func (e *Engine) bestBundleMatch(matches []waf.Match, p *model.Proxy) (waf.Match, bool) {
	best := waf.Match{}
	severity := 999
	ok := false
	for _, m := range matches {
		if m.Origin != "bundle" || e.bundleMode(p, m.Bundle) == model.BundleOff {
			continue
		}
		if m.Severity < severity {
			best, severity, ok = m, m.Severity, true
		}
	}
	return best, ok
}

// bundleMode reads the mode for a bundle on a proxy's profile. A site without
// a profile keeps the default log mode, matching an unconfigured profile.
func (e *Engine) bundleMode(p *model.Proxy, name string) string {
	if p == nil || p.ProfileID == nil {
		return model.BundleLog
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	prof, ok := e.profiles[*p.ProfileID]
	if !ok {
		return model.BundleLog
	}
	return prof.BundleMode(name)
}

// normVerdict turns a normalization finding into a verdict according to the
// configured mode: log it, or refuse the request.
func (e *Engine) normVerdict(findings []norm.Finding) (model.Verdict, bool) {
	if len(findings) == 0 {
		return model.Verdict{}, false
	}
	e.mu.RLock()
	mode := e.settings.NormalizationMode
	e.mu.RUnlock()
	if mode == "off" {
		return model.Verdict{}, false
	}
	f := findings[0]
	id := norm.RuleDuplicate
	reason := "duplicate parameter " + strconv.Quote(f.Parameter) + " in the " + f.Source
	if f.Kind == "double-encoded" {
		id = norm.RuleDoubleEncoded
		reason = "parameter " + strconv.Quote(f.Parameter) + " in the " + f.Source +
			" decodes twice: " + strconv.Quote(f.First) + " then " + strconv.Quote(f.Second)
	}
	v := model.Verdict{Action: "log", Stage: "waf", Rule: strconv.Itoa(id),
		Reason: reason, Status: http.StatusOK}
	if mode == "block" {
		v.Action, v.Status = "block", http.StatusForbidden
	}
	return v, true
}

// InList reports whether an address or its country is named by any of the given
// named lists. It answers an empty id set with false; a list that no longer
// exists matches nothing, so a deleted list fails closed.
func (e *Engine) InList(req *Request, ids []int64) bool {
	if req == nil || len(ids) == 0 {
		return false
	}
	addr, country := req.Addr, req.Loc.Country
	country = strings.ToUpper(country)
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, id := range ids {
		l, ok := e.lists[id]
		if !ok {
			continue
		}
		for _, pr := range l.ips {
			if pr.Contains(addr) {
				return true
			}
		}
		if country != "" && l.countries[country] {
			return true
		}
	}
	return false
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
