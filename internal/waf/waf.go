// Package waf wraps OWASP Coraza with the Core Rule Set and maps rule IDs to
// human readable attack categories.
package waf

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/norm"
)

// Result describes what the WAF decided about one request.
type Result struct {
	Matched   bool   `json:"matched"`
	Blocked   bool   `json:"blocked"`
	RuleID    int    `json:"rule_id"`
	Message   string `json:"message"`
	Label     string `json:"label"`
	Paranoia  int    `json:"paranoia"`
	ProfileID int64  `json:"profile_id"`
	// Norm lists request encodings to flag. The policy layer decides whether
	// the configured normalization mode logs or blocks them.
	Norm []norm.Finding `json:"-"`
}

// BundleRule is one signature rule delivered by the signed bundle channel.
// Target and Operator are Coraza variables and an operator expression; the
// pack never carries whole directives, so a rule cannot reconfigure the
// engine.
type BundleRule struct {
	ID       int    `json:"id"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Tag      string `json:"tag,omitempty"`
	Target   string `json:"target"`
	Operator string `json:"operator"`
}

// Bundle is one installed signature pack.
type Bundle struct {
	Name    string       `json:"name"`
	Version string       `json:"version"`
	Rules   []BundleRule `json:"rules"`
}

// BundleRuleFirst and BundleRuleLast bound the rule-ID range reserved for
// bundles. CRS v4 ships rules up to 980170, so the range starts above that and
// stops at the 999999 exception cap; the anomaly scorer's 949000–950000 and
// every CRS ID stay outside it, which is what lets the console tell a bundle
// hit from a CRS hit by the ID alone.
const (
	BundleRuleFirst = 990000
	BundleRuleLast  = 999999
)

// IsBundleRule reports whether a rule ID belongs to the bundle range.
func IsBundleRule(id int) bool { return id >= BundleRuleFirst && id <= BundleRuleLast }

// Engine is a compiled WAF for one protection profile.
type Engine struct {
	id         int64
	name       string
	paranoia   int
	maxBody    int64
	exceptions map[int]bool
	bundles    map[int]bundleOrigin
	waf        coraza.WAF
}

// bundleOrigin names the pack a rule came from, so a verdict can say which
// bundle matched instead of only which ID fired.
type bundleOrigin struct {
	name    string
	version string
}

// Set lazily compiles and caches one engine per profile.
type Set struct {
	log      *slog.Logger
	mu       sync.RWMutex
	configs  map[int64]model.Profile
	bundles  []Bundle
	engines  map[int64]*Engine
	fallback *Engine
}

// NewSet builds a set from the profile table. Engines compile on first use to
// keep idle memory low; the Common profile is compiled eagerly because every
// request can fall back to it.
func NewSet(profiles []model.Profile, log *slog.Logger) *Set {
	s := &Set{
		log:     log,
		configs: map[int64]model.Profile{},
		engines: map[int64]*Engine{},
	}
	for _, p := range profiles {
		s.configs[p.ID] = p
	}
	fallback := model.Profile{ID: 0, Name: "Default", Mode: "block", Paranoia: 1, Anomaly: 5, MaxBody: 131072}
	if eng, err := compile(fallback, nil); err == nil {
		s.fallback = eng
	} else {
		log.Error("compile fallback WAF", "err", err)
	}
	return s
}

// Reload replaces the profile configuration and drops compiled engines.
func (s *Set) Reload(profiles []model.Profile) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configs = map[int64]model.Profile{}
	for _, p := range profiles {
		s.configs[p.ID] = p
	}
	s.engines = map[int64]*Engine{}
}

// SetBundles replaces the installed signature packs. Every profile engine is
// dropped because a bundle's rules and its off/log/block mode are baked in at
// compile time, which is what makes "off" cost nothing at request time.
func (s *Set) SetBundles(bundles []Bundle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundles = bundles
	s.engines = map[int64]*Engine{}
	// The fallback profile is what a site without a profile gets. Recompile it
	// too, or those sites would silently see no bundle rules at all.
	fallback := model.Profile{ID: 0, Name: "Default", Mode: "block", Paranoia: 1, Anomaly: 5, MaxBody: 131072}
	if eng, err := compile(fallback, bundles); err == nil {
		s.fallback = eng
	} else {
		s.log.Error("compile fallback WAF", "err", err)
	}
}

// For returns the engine for a profile, compiling it on first use.
func (s *Set) For(profileID *int64) *Engine {
	if profileID == nil {
		return s.fallback
	}
	id := *profileID
	s.mu.RLock()
	if e, ok := s.engines[id]; ok {
		s.mu.RUnlock()
		return e
	}
	cfg, ok := s.configs[id]
	bundles := s.bundles
	s.mu.RUnlock()
	if !ok {
		return s.fallback
	}
	eng, err := compile(cfg, bundles)
	if err != nil {
		s.log.Error("compile WAF profile", "profile", cfg.Name, "err", err)
		return s.fallback
	}
	s.mu.Lock()
	s.engines[id] = eng
	s.mu.Unlock()
	return eng
}

func compile(p model.Profile, bundles []Bundle) (*Engine, error) {
	paranoia := p.Paranoia
	if paranoia < 1 || paranoia > 4 {
		paranoia = 1
	}
	threshold := p.Anomaly
	if threshold < 1 || threshold > 100 {
		threshold = 5
	}
	maxBody := p.MaxBody
	if maxBody < 1024 {
		maxBody = 131072
	}
	// Exceptions must be compiled in as SecRuleRemoveById: filtering matched
	// rules after the transaction has already been interrupted would let the
	// CRS anomaly aggregator block on a rule the operator disabled.
	exceptions := map[int]bool{}
	var remove []string
	for _, part := range strings.Split(p.Exceptions, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.Atoi(part)
		if err != nil || id < 1 || id > 999999 {
			continue
		}
		exceptions[id] = true
		remove = append(remove, strconv.Itoa(id))
	}
	// A transaction that starts at the response phase never runs the CRS setup,
	// so the phase-3 action restores the thresholds and scores the request
	// phase would have set.
	directives := fmt.Sprintf(`Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit %d
SecRequestBodyInMemoryLimit %d
SecRequestBodyNoFilesLimit %d
SecAction "id:9001001,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=%d"
SecAction "id:9001002,phase:1,nolog,pass,t:none,setvar:tx.detection_paranoia_level=%d"
SecAction "id:9001003,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=%d"
SecAction "id:9001004,phase:3,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d,setvar:tx.outbound_anomaly_score_threshold=%d,setvar:tx.critical_anomaly_score=5,setvar:tx.error_anomaly_score=4,setvar:tx.warning_anomaly_score=3,setvar:tx.notice_anomaly_score=2"
`, maxBody, maxBody, maxBody, paranoia, paranoia, threshold, paranoia, paranoia, threshold)
	if len(remove) > 0 {
		directives += "SecRuleRemoveById " + strings.Join(remove, " ") + "\n"
	}
	// A scanner can put the target file in the path instead of a parameter.
	// The CRS LFI rules inspect arguments, so "?file=/etc/passwd" was blocked
	// while a bare "/etc/passwd" reached the backend. The path is already
	// canonicalised by the caller, so this matches what the upstream would
	// open. The trailing boundary keeps ordinary files such as
	// "/etc/passwd-docs" out of the rule.
	directives += `SecRule REQUEST_FILENAME "@rx (?i)(?:^|/)(?:etc/(?:passwd|shadow|group|gshadow|sudoers)|proc/(?:self|[0-9]+)/(?:environ|cmdline)|\.ssh/(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys))(?:/|$)" "id:900110,phase:1,deny,status:403,log,severity:'CRITICAL',tag:'attack-lfi',msg:'path-style file access probe'"
`

	origins := map[int]bundleOrigin{}
	directives += bundleDirectives(p, bundles, origins)

	w, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(directives))
	if err != nil {
		return nil, fmt.Errorf("compile %s: %w", p.Name, err)
	}
	return &Engine{
		id:         p.ID,
		name:       p.Name,
		paranoia:   paranoia,
		maxBody:    maxBody,
		exceptions: exceptions,
		bundles:    origins,
		waf:        w,
	}, nil
}

// bundleDirectives turns the installed packs into phase-1 rules for one
// profile. A rule only matches: the policy layer decides whether the verdict
// is a block or a log, which is what lets the same pack block on one profile
// and stay quiet on another. A bundle set to off contributes no rules at all.
// ValidateBundle checks a downloaded pack before it can replace a working one.
// It rejects the whole pack when any rule is unusable, so a publisher mistake
// cannot half-apply.
func ValidateBundle(b Bundle) error {
	if strings.TrimSpace(b.Name) == "" || len(b.Name) > 64 {
		return errors.New("bundle has no usable name")
	}
	if strings.TrimSpace(b.Version) == "" || len(b.Version) > 64 {
		return fmt.Errorf("bundle %s has no usable version", b.Name)
	}
	if len(b.Rules) == 0 {
		return fmt.Errorf("bundle %s contains no rules", b.Name)
	}
	seen := map[int]bool{}
	for _, r := range b.Rules {
		if !ruleValid(r) {
			return fmt.Errorf("bundle %s has an unusable rule %d", b.Name, r.ID)
		}
		if seen[r.ID] {
			return fmt.Errorf("bundle %s repeats rule %d", b.Name, r.ID)
		}
		seen[r.ID] = true
	}
	return nil
}

// ValidateCompile proves a pack compiles in a throwaway engine. Coraza rejects
// malformed operators at load time, and a profile must never fall back to the
// default engine because a downloaded rule was bad.
func ValidateCompile(name string, rules []BundleRule) error {
	p := model.Profile{Name: "bundle-check", Mode: "block", Paranoia: 1, Anomaly: 5, MaxBody: 131072}
	origins := map[int]bundleOrigin{}
	directives := bundleDirectives(p, []Bundle{{Name: name, Version: "check", Rules: rules}}, origins)
	if origins == nil || len(origins) == 0 {
		return errors.New("bundle produced no usable directives")
	}
	cfg := coraza.NewWAFConfig().WithRootFS(coreruleset.FS).WithDirectives("SecRuleEngine On\n" + directives)
	if _, err := coraza.NewWAF(cfg); err != nil {
		return fmt.Errorf("bundle does not compile: %w", err)
	}
	return nil
}

// ruleValid applies the shape checks that keep a pack from breaking out of its
// own directive or reconfiguring the engine.
func ruleValid(r BundleRule) bool {
	if !IsBundleRule(r.ID) || len(r.Message) == 0 || len(r.Message) > 512 {
		return false
	}
	severity := strings.ToUpper(strings.TrimSpace(r.Severity))
	return validBundleSeverity(severity) && validBundleTarget(r.Target) && validBundleOperator(r.Operator)
}

func bundleDirectives(p model.Profile, bundles []Bundle, origins map[int]bundleOrigin) string {
	var out strings.Builder
	seen := map[int]bool{}
	for _, b := range bundles {
		if p.BundleMode(b.Name) == model.BundleOff {
			continue
		}
		name := safeTagValue(b.Name)
		version := safeTagValue(b.Version)
		for _, r := range b.Rules {
			if seen[r.ID] || !ruleValid(r) {
				continue
			}
			severity := strings.ToUpper(strings.TrimSpace(r.Severity))
			seen[r.ID] = true
			origins[r.ID] = bundleOrigin{name: b.Name, version: b.Version}
			fmt.Fprintf(&out, "SecRule %s \"%s\" \"id:%d,phase:1,pass,log,severity:'%s',tag:'bundle:%s',tag:'bundle-version:%s',msg:'%s'\"\n",
				r.Target, escapeDirective(r.Operator), r.ID, severity, name, version, escapeDirective(r.Message))
		}
	}
	return out.String()
}

// safeTagValue keeps a bundle name or version from breaking out of a tag.
func safeTagValue(v string) string {
	var b strings.Builder
	for _, r := range v {
		if r == '.' || r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func escapeDirective(v string) string {
	var b strings.Builder
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			b.WriteByte(' ')
			continue
		}
		if r == '\\' || r == '\'' || r == '"' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func validBundleSeverity(s string) bool {
	switch s {
	case "EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG":
		return true
	}
	return false
}

// validBundleTarget accepts a Coraza variable list such as "ARGS|REQUEST_URI".
func validBundleTarget(s string) bool {
	if s == "" || len(s) > 200 {
		return false
	}
	for _, r := range s {
		if r == '_' || r == '|' || r == ',' || r == '&' || r == '!' || r == ' ' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			continue
		}
		return false
	}
	return true
}

func validBundleOperator(s string) bool {
	if len(s) < 2 || len(s) > 4096 || !strings.HasPrefix(s, "@") {
		return false
	}
	return !strings.ContainsAny(s, "\r\n")
}

// MaxBody returns the inspected body limit.
func (e *Engine) MaxBody() int64 {
	if e == nil || e.maxBody <= 0 {
		return 131072
	}
	return e.maxBody
}

// Name returns the profile name.
func (e *Engine) Name() string {
	if e == nil {
		return "default"
	}
	return e.name
}

// Match is one rule that fired during inspection.
type Match struct {
	RuleID     int    `json:"rule_id"`
	Message    string `json:"message"`
	Severity   int    `json:"severity"`
	Disruptive bool   `json:"disruptive"`
	// Origin is crs or bundle; Bundle and BundleVersion name the pack when the
	// rule came from one. The policy layer resolves off/log/block per origin.
	Origin        string `json:"origin"`
	Bundle        string `json:"bundle,omitempty"`
	BundleVersion string `json:"bundle_version,omitempty"`
}

// Inspect evaluates a request. The body must already be read and limited by the
// caller; nil means no body. It never panics on malformed input.
func (e *Engine) Inspect(r *http.Request, body []byte, clientIP netip.Addr) Result {
	res, _ := e.InspectAll(r, body, clientIP)
	return res
}

// InspectAll is Inspect plus every attack rule that matched, so the request
// simulator can list them instead of only the one the log would name.
func (e *Engine) InspectAll(r *http.Request, body []byte, clientIP netip.Addr) (res Result, matches []Match) {
	if e == nil || e.waf == nil {
		return res, nil
	}
	defer func() {
		if rec := recover(); rec != nil {
			// Fail closed: an engine panic must never forward an uninspected
			// request. Detect-only profiles still log the block without
			// enforcing it, because the mode is applied by the policy layer.
			res = Result{Matched: true, Blocked: true, RuleID: 200006,
				Message: "request inspection failed", Label: "protocol-violation"}
			matches = nil
		}
	}()

	res.Norm = norm.Inspect(r, body)

	tx := e.waf.NewTransaction()
	defer tx.Close()

	if clientIP.IsValid() {
		tx.ProcessConnection(clientIP.String(), 0, "", 0)
	}
	uri := r.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}
	tx.ProcessURI(uri, r.Method, r.Proto)
	for k, vals := range r.Header {
		for _, v := range vals {
			tx.AddRequestHeader(k, v)
		}
	}
	tx.AddRequestHeader("Host", r.Host)
	tx.ProcessRequestHeaders()
	if len(body) > 0 {
		if _, _, err := tx.WriteRequestBody(body); err != nil {
			// Fail closed: a body the engine could not consume (for example one
			// above the profile limit) must never be forwarded uninspected.
			res.Matched = true
			res.Blocked = true
			res.RuleID = 200004
			res.Message = "request body rejected by the WAF body limit"
			res.Label = "protocol-violation"
			return res, nil
		}
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		res.Matched = true
		res.Blocked = true
		res.RuleID = 200005
		res.Message = "request body could not be inspected"
		res.Label = "protocol-violation"
		return res, nil
	}

	return e.summarise(res, tx.MatchedRules(), tx.IsInterrupted(), tx.Interruption())
}

// ResponseInput is one upstream response handed to the response rules.
type ResponseInput struct {
	Status int
	Proto  string
	Header http.Header
	Body   []byte
}

// InspectResponse runs the CRS response phases. It reports the same shape as
// InspectAll so the proxy can log a response verdict like a request one.
func (e *Engine) InspectResponse(in ResponseInput) (res Result, matches []Match) {
	if e == nil || e.waf == nil {
		return res, nil
	}
	defer func() {
		if rec := recover(); rec != nil {
			res = Result{Matched: true, Blocked: true, RuleID: 200007,
				Message: "response inspection failed", Label: "protocol-violation"}
			matches = nil
		}
	}()
	if in.Status == 0 {
		in.Status = http.StatusOK
	}
	if in.Proto == "" {
		in.Proto = "HTTP/1.1"
	}

	tx := e.waf.NewTransaction()
	defer tx.Close()
	for k, vals := range in.Header {
		for _, v := range vals {
			tx.AddResponseHeader(k, v)
		}
	}
	tx.ProcessResponseHeaders(in.Status, in.Proto)
	if _, _, err := tx.WriteResponseBody(in.Body); err != nil {
		return Result{Matched: true, Blocked: true, RuleID: 200008, ProfileID: e.id, Paranoia: e.paranoia,
			Message: "response body rejected by the WAF body limit", Label: "protocol-violation"}, nil
	}
	if _, err := tx.ProcessResponseBody(); err != nil {
		return Result{Matched: true, Blocked: true, RuleID: 200009, ProfileID: e.id, Paranoia: e.paranoia,
			Message: "response body could not be inspected", Label: "protocol-violation"}, nil
	}
	return e.summarise(res, tx.MatchedRules(), tx.IsInterrupted(), tx.Interruption())
}

// summarise turns the transaction's matched rules into the verdict both the
// request and the response path report.
func (e *Engine) summarise(res Result, matched []types.MatchedRule, interrupted bool, interruption *types.Interruption) (Result, []Match) {
	bestID, bestMsg, bestSeverity := 0, "", 999
	excepted := 0
	blockedByRule := false
	found := []Match{}
	for _, mr := range matched {
		id := mr.Rule().ID()
		if id == 0 {
			continue
		}
		if e.exceptions[id] {
			excepted++
			continue
		}
		// Anomaly aggregator rules are not themselves the attack.
		if id >= 949000 && id < 950000 {
			continue
		}
		// Setup actions (the CRS version marker, body-inspection toggles) match
		// without a severity and would otherwise win every report, so only rules
		// that classify an attack are candidates for the logged rule.
		sev := int(mr.Rule().Severity())
		if sev >= 0 {
			m := Match{RuleID: id, Message: mr.Message(), Severity: sev, Disruptive: mr.Disruptive(), Origin: "crs"}
			if IsBundleRule(id) {
				m.Origin = "bundle"
				if o, ok := e.bundles[id]; ok {
					m.Bundle, m.BundleVersion = o.name, o.version
				}
			}
			found = append(found, m)
		}
		if sev >= 0 && sev < bestSeverity {
			bestSeverity = sev
			bestID = id
			bestMsg = mr.Message()
		}
		if mr.Disruptive() && mr.Rule().ID() != 0 {
			blockedByRule = true
		}
	}
	// Setup actions (the paranoia and threshold SecActions) match on every
	// request. Counting them would make every clean request look like a hit and
	// the policy layer would log it as a WAF event.
	res.Matched = len(found) > 0
	res.ProfileID = e.id
	res.Paranoia = e.paranoia
	if bestID == 0 && interruption != nil {
		bestID = interruption.RuleID
		bestMsg = "request blocked by rule " + strconv.Itoa(interruption.RuleID)
	}
	res.RuleID = bestID
	res.Message = bestMsg
	res.Label = Label(bestID)

	// If every matched rule is excepted, the interruption is not actionable.
	if len(matched) > 0 && excepted == len(matched) {
		res.Matched = false
		res.Blocked = false
		return res, nil
	}
	if interrupted {
		res.Blocked = true
	} else if blockedByRule {
		res.Blocked = false // detection-only: remember the match, do not block
	}
	return res, found
}

// Label maps a CRS rule ID to a short attack category.
func Label(ruleID int) string {
	switch ruleID {
	case 900110:
		return "lfi"
	case norm.RuleDuplicate, norm.RuleDoubleEncoded:
		return "normalization"
	}
	switch ruleID / 1000 {
	case 913:
		return "scanner"
	case 920, 921:
		return "protocol-violation"
	case 930:
		return "lfi"
	case 931:
		return "rfi"
	case 932:
		return "rce"
	case 933:
		return "php-injection"
	case 934:
		return "node-injection"
	case 935:
		return "ssrf"
	case 941:
		return "xss"
	case 942:
		return "sqli"
	case 943, 945:
		return "session-fixation"
	case 944:
		return "java-injection"
	case 947:
		return "webshell"
	}
	switch ruleID {
	case 932160:
		return "unix-shell"
	case 944100:
		return "log4shell"
	}
	if ruleID == 0 {
		return "waf"
	}
	return "waf"
}
