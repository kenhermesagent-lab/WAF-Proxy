package policy

import (
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

// SimRequest is one synthetic request to replay through the pipeline.
type SimRequest struct {
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

// SimStage is one pipeline stage's outcome.
type SimStage struct {
	Stage   string   `json:"stage"`
	Verdict string   `json:"verdict"`
	Reason  string   `json:"reason,omitempty"`
	RuleIDs []string `json:"rule_ids,omitempty"`
	Skipped string   `json:"skipped,omitempty"`
}

// SimException is the profile change that would stop a blocked rule, with the
// other hosts that share the profile so its blast radius is visible first.
type SimException struct {
	ProfileID  int64    `json:"profile_id"`
	Profile    string   `json:"profile"`
	RuleID     int      `json:"rule_id"`
	OtherHosts []string `json:"other_hosts"`
}

// SimResult is what would happen to a request, stage by stage.
type SimResult struct {
	Verdict   model.Verdict `json:"verdict"`
	Stages    []SimStage    `json:"stages"`
	Matches   []waf.Match   `json:"matches"`
	Upstream  string        `json:"upstream,omitempty"`
	Route     string        `json:"route,omitempty"`
	Truncated bool          `json:"truncated"`
	Notes     []string      `json:"notes"`
	Exception *SimException `json:"exception,omitempty"`
}

// Simulate replays a request through the stages that can be decided locally.
// It never spends a rate-limit budget, writes a ban, opens the access gate or
// calls forward auth; those stages are reported as skipped instead.
func (e *Engine) Simulate(in SimRequest) SimResult {
	res := SimResult{
		Stages:  []SimStage{},
		Matches: []waf.Match{},
		Notes:   []string{"the access gate and forward auth were not performed"},
	}
	if in.Proxy == nil {
		return res
	}
	host := in.Host
	if host == "" {
		host = in.Proxy.Hostname
	}
	hreq := in.HTTP
	if hreq == nil {
		hreq = &http.Request{Method: in.Method, URL: &url.URL{Path: in.Path, RawQuery: in.Query},
			Host: host, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{}}
		hreq.RequestURI = hreq.URL.RequestURI()
	}
	req := Request{
		Proxy: in.Proxy, Host: host, Method: in.Method, Path: in.Path,
		Query: in.Query, UA: in.UA, Addr: in.Addr, Loc: in.Loc, Body: in.Body, HTTP: hreq,
	}

	// A ban is the first stage and ends the pipeline, exactly as Screen does.
	if rec, ok := e.bans.Match(in.Addr); ok {
		stage := "temp-ban"
		if rec.Permanent {
			stage = "permanent-ban"
		}
		res.Verdict = model.Verdict{Action: "ban", Stage: stage, Rule: rec.CIDR,
			Reason: rec.Reason, Status: http.StatusForbidden, BanSource: rec.Source}
		res.Stages = append(res.Stages, SimStage{Stage: stage, Verdict: "ban",
			Reason: rec.Reason, RuleIDs: []string{rec.CIDR}})
		return res
	}

	overall := e.screen(&req, false)
	res.Stages = append(res.Stages, screenStage(overall))
	if overall.Action != "allow" && overall.Action != "log" {
		res.Verdict = overall
		return e.withException(res, in)
	}
	res.Stages = append(res.Stages, SimStage{Stage: "rate-limit", Verdict: "skipped",
		Skipped: "state is per client; a simulation must not spend it"})

	// A trusted source skips the WAF, so the stage is reported as skipped. The
	// rules are still evaluated so an operator can see what the exemption lets
	// through; nothing is refused on that basis.
	if ok, lists := e.WAFSkip(&req); ok {
		verdict, _, matches := e.inspect(&req)
		res.Matches = matches
		stage := SimStage{Stage: "waf-skip", Verdict: "skipped",
			Skipped: "this source is trusted by the access profile, so CRS inspection is skipped"}
		if len(lists) > 0 {
			stage.Skipped += " (trust lists: " + strings.Join(lists, ", ") + ")"
		}
		for _, m := range matches {
			stage.RuleIDs = append(stage.RuleIDs, strconv.Itoa(m.RuleID))
		}
		if verdict.Action == "block" || verdict.Action == "log" {
			stage.Skipped += "; the request would have been " + verdict.Action + "ed: " + verdict.Reason
		}
		res.Stages = append(res.Stages, stage)
		res.Verdict = overall
		return e.withException(res, in)
	}

	verdict, _, matches := e.inspect(&req)
	res.Matches = matches
	wafStage := SimStage{Stage: "waf", Verdict: verdict.Action, Reason: verdict.Reason}
	for _, m := range matches {
		wafStage.RuleIDs = append(wafStage.RuleIDs, strconv.Itoa(m.RuleID))
	}
	if len(wafStage.RuleIDs) == 0 && verdict.Rule != "" {
		wafStage.RuleIDs = []string{verdict.Rule}
	}
	res.Stages = append(res.Stages, wafStage)
	if verdict.Action == "block" || verdict.Action == "log" {
		overall = verdict
	}
	res.Verdict = overall
	return e.withException(res, in)
}

// screenStage names the policy stage that refused the request, or "screen" when
// it allowed it.
func screenStage(v model.Verdict) SimStage {
	s := SimStage{Stage: "screen", Verdict: v.Action, Reason: v.Reason}
	if v.Action != "allow" && v.Stage != "" {
		s.Stage = v.Stage
	}
	if v.Rule != "" {
		s.RuleIDs = []string{v.Rule}
	}
	return s
}

// withException adds the profile edit that would except a WAF block.
func (e *Engine) withException(res SimResult, in SimRequest) SimResult {
	v := res.Verdict
	if v.Action != "block" || v.Stage != "waf" || in.Proxy.ProfileID == nil {
		return res
	}
	ruleID, err := strconv.Atoi(v.Rule)
	if err != nil || ruleID == 0 {
		return res
	}
	prof, err := e.st.GetProfile(*in.Proxy.ProfileID)
	if err != nil {
		return res
	}
	others := []string{}
	proxies, err := e.st.ListProxies()
	if err == nil {
		for _, p := range proxies {
			if p.ID != in.Proxy.ID && p.ProfileID != nil && *p.ProfileID == prof.ID {
				others = append(others, p.Hostname)
			}
		}
	}
	res.Exception = &SimException{ProfileID: prof.ID, Profile: prof.Name, RuleID: ruleID, OtherHosts: others}
	return res
}
