// Package waf wraps OWASP Coraza with the Core Rule Set and maps rule IDs to
// human readable attack categories.
package waf

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
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
}

// Engine is a compiled WAF for one protection profile.
type Engine struct {
	id         int64
	name       string
	paranoia   int
	maxBody    int64
	exceptions map[int]bool
	waf        coraza.WAF
}

// Set lazily compiles and caches one engine per profile.
type Set struct {
	log      *slog.Logger
	mu       sync.RWMutex
	configs  map[int64]model.Profile
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
	if eng, err := compile(fallback); err == nil {
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
	s.mu.RUnlock()
	if !ok {
		return s.fallback
	}
	eng, err := compile(cfg)
	if err != nil {
		s.log.Error("compile WAF profile", "profile", cfg.Name, "err", err)
		return s.fallback
	}
	s.mu.Lock()
	s.engines[id] = eng
	s.mu.Unlock()
	return eng
}

func compile(p model.Profile) (*Engine, error) {
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
`, maxBody, maxBody, maxBody, paranoia, paranoia, threshold)
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
		waf:        w,
	}, nil
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

// Inspect evaluates a request. The body must already be read and limited by the
// caller; nil means no body. It never panics on malformed input.
func (e *Engine) Inspect(r *http.Request, body []byte, clientIP netip.Addr) (res Result) {
	if e == nil || e.waf == nil {
		return res
	}
	defer func() {
		if rec := recover(); rec != nil {
			// Fail closed: an engine panic must never forward an uninspected
			// request. Detect-only profiles still log the block without
			// enforcing it, because the mode is applied by the policy layer.
			res = Result{Matched: true, Blocked: true, RuleID: 200006,
				Message: "request inspection failed", Label: "protocol-violation"}
		}
	}()

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
			return res
		}
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		res.Matched = true
		res.Blocked = true
		res.RuleID = 200005
		res.Message = "request body could not be inspected"
		res.Label = "protocol-violation"
		return res
	}

	matched := tx.MatchedRules()
	bestID, bestMsg, bestSeverity := 0, "", 999
	excepted := 0
	blockedByRule := false
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
		if sev >= 0 && sev < bestSeverity {
			bestSeverity = sev
			bestID = id
			bestMsg = mr.Message()
		}
		if mr.Disruptive() && mr.Rule().ID() != 0 {
			blockedByRule = true
		}
	}
	interrupted := tx.IsInterrupted()
	interruption := tx.Interruption()

	res.Matched = len(matched) > 0
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
		return res
	}
	if interrupted {
		res.Blocked = true
	} else if blockedByRule {
		res.Blocked = false // detection-only: remember the match, do not block
	}
	return res
}

// Label maps a CRS rule ID to a short attack category.
func Label(ruleID int) string {
	switch ruleID {
	case 900110:
		return "lfi"
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
