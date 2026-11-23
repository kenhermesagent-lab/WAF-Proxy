package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/acme"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/intel"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/internalca"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/notify"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/preset"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/proxy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/urlguard"
)

// ---------- proxies ----------

type upstreamBody struct {
	// ID and ProxyID are accepted because the GUI round-trips the objects it
	// reads back; they are ignored on write.
	ID      int64  `json:"id"`
	ProxyID int64  `json:"proxy_id"`
	URL     string `json:"url"`
	Weight  int    `json:"weight"`
	// Enabled is a pointer so an omitted field means "on": a caller that only
	// names the target must not end up with a site that has no live upstream.
	Enabled  *bool `json:"enabled"`
	MaxConns int   `json:"max_conns"`
}

type proxyBody struct {
	// ID is accepted but the path parameter is authoritative.
	ID                  int64  `json:"id"`
	Hostname            string `json:"hostname"`
	Enabled             *bool  `json:"enabled"`
	ProfileID           *int64 `json:"profile_id"`
	CertID              *int64 `json:"cert_id"`
	ProtectionProfileID *int64 `json:"protection_profile_id"`
	AccessProfileID     *int64 `json:"access_profile_id"`
	AuthProviderID      *int64 `json:"auth_provider_id"`
	GateMode            string `json:"gate_mode"`
	GateSecret          string `json:"gate_secret"`
	Fingerprint         string `json:"fingerprint"`
	BotLevel            string `json:"bot_level"`
	Maintenance         *bool  `json:"maintenance"`
	WAFMode             string `json:"waf_mode"`
	// Balancing, health and capacity settings are per site; an omitted number
	// keeps the stored value, so an older client cannot reset them.
	LBPolicy             string           `json:"lb_policy"`
	HealthPath           string           `json:"health_path"`
	HealthExpect         string           `json:"health_expect"`
	HealthInterval       *int             `json:"health_interval"`
	HealthFailAfter      *int             `json:"health_fail_after"`
	MaxInflight          *int             `json:"max_inflight"`
	MaxInflightPerClient *int             `json:"max_inflight_per_client"`
	UpstreamTimeout      *int             `json:"upstream_timeout"`
	Retries              *int             `json:"retries"`
	RequestHeaders       []model.HeaderOp `json:"request_headers"`
	ResponseHeaders      []model.HeaderOp `json:"response_headers"`
	TLSMinVersion        string           `json:"tls_min_version"`
	// Preset names an application preset to turn into a WAF profile when the
	// proxy is created. It is ignored on update: the profile is edited directly
	// from then on.
	Preset    string         `json:"preset"`
	Upstreams []upstreamBody `json:"upstreams"`
	Routes    []model.Route  `json:"routes"`
	GateUsers []string       `json:"gate_users"`
}

type proxyView struct {
	model.Proxy
	Upstreams []model.Upstream `json:"upstreams"`
	Routes    []model.Route    `json:"routes"`
	GateUsers []string         `json:"gate_users"`
	Requests  int64            `json:"requests"`
	Blocked   int64            `json:"blocked"`
}

func (s *Server) listProxies(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListProxies()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	met := s.metrics.Snapshot()
	out := make([]proxyView, 0, len(list))
	for _, p := range list {
		v := proxyView{Proxy: p}
		v.Upstreams, _ = s.st.ListUpstreams(p.ID)
		v.Routes, _ = s.st.ListRoutes(p.ID)
		v.GateUsers, _ = s.st.GateACL(p.ID)
		if c := met.Proxies[strconv.FormatInt(p.ID, 10)]; c != nil {
			v.Requests, v.Blocked = c.Requests, c.Blocked
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createProxy(w http.ResponseWriter, r *http.Request) {
	var in proxyBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if msg := s.validateHostname(in.Hostname); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	p := &model.Proxy{
		Hostname: strings.ToLower(strings.TrimSpace(in.Hostname)),
		Enabled:  in.Enabled == nil || *in.Enabled,
		CertID:   in.CertID, ProfileID: in.ProfileID,
		ProtectionProfileID: in.ProtectionProfileID, AccessProfileID: in.AccessProfileID,
		AuthProviderID:  in.AuthProviderID,
		GateMode:        defaultStr(in.GateMode, "off"),
		Fingerprint:     defaultStr(in.Fingerprint, "strict"),
		BotLevel:        defaultStr(in.BotLevel, "light"),
		WAFMode:         defaultStr(in.WAFMode, "inherit"),
		LBPolicy:        defaultStr(in.LBPolicy, proxy.LBWeightedRR),
		HealthPath:      defaultStr(in.HealthPath, "/"),
		HealthExpect:    defaultStr(in.HealthExpect, "200-399"),
		RequestHeaders:  in.RequestHeaders,
		ResponseHeaders: in.ResponseHeaders,
		TLSMinVersion:   in.TLSMinVersion,
	}
	applyProxyNumbers(p, in)
	if in.Maintenance != nil {
		p.Maintenance = *in.Maintenance
	}
	s.inheritAccessProfile(p)
	if msg := validateProxyOptions(in); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if msg := validateUpstreams(in.Upstreams); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if msg := s.checkAuthProvider(in.AuthProviderID); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if msg := requireGateSecret(p.GateMode, "", in.GateSecret); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if p.GateMode == "passphrase" && in.GateSecret != "" {
		enc, err := s.box.Seal(in.GateSecret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encryption error")
			return
		}
		p.GateSecret = enc
	}
	var fromPreset *int64
	if in.Preset != "" {
		pre, ok := preset.Get(in.Preset)
		if !ok {
			writeError(w, http.StatusBadRequest, "unknown application preset")
			return
		}
		prof := pre.Profile(p.Hostname)
		if err := s.st.CreateProfile(&prof); err != nil {
			writeError(w, http.StatusInternalServerError, "cannot create the preset's WAF profile")
			return
		}
		p.ProfileID = &prof.ID
		fromPreset = &prof.ID
	}
	id, err := s.st.CreateProxy(p)
	if err != nil {
		// The profile was only created for this proxy; leaving it behind would
		// litter the list every time a duplicate hostname was offered.
		if fromPreset != nil {
			_ = s.st.DeleteProfile(*fromPreset)
		}
		writeError(w, http.StatusConflict, "hostname already exists")
		return
	}
	s.saveChildren(id, in)
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "proxy.create", p.Hostname, clientIP(r))
	p.ID = id
	writeJSON(w, http.StatusCreated, p)
}

// inheritAccessProfile fills the WAF and protection profile from the selected
// access profile when the caller did not name them explicitly, so an operator
// can create a host by choosing one thing. An explicit choice still wins.
func (s *Server) inheritAccessProfile(p *model.Proxy) {
	if p == nil || p.AccessProfileID == nil {
		return
	}
	ap, err := s.st.GetAccessProfile(*p.AccessProfileID)
	if err != nil {
		return
	}
	if p.ProfileID == nil {
		p.ProfileID = ap.WAFProfileID
	}
	if p.ProtectionProfileID == nil {
		p.ProtectionProfileID = ap.ProtectionProfileID
	}
}

func (s *Server) updateProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	current, err := s.st.GetProxy(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	var in proxyBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if in.Hostname != "" && in.Hostname != current.Hostname {
		if msg := s.validateHostname(in.Hostname); msg != "" {
			writeError(w, http.StatusBadRequest, msg)
			return
		}
		current.Hostname = strings.ToLower(strings.TrimSpace(in.Hostname))
	}
	if in.Enabled != nil {
		current.Enabled = *in.Enabled
	}
	if in.Maintenance != nil {
		current.Maintenance = *in.Maintenance
	}
	current.CertID = in.CertID
	current.ProfileID = in.ProfileID
	current.ProtectionProfileID = in.ProtectionProfileID
	current.AccessProfileID = in.AccessProfileID
	current.AuthProviderID = in.AuthProviderID
	s.inheritAccessProfile(current)
	if in.GateMode != "" {
		current.GateMode = in.GateMode
	}
	if in.Fingerprint != "" {
		current.Fingerprint = in.Fingerprint
	}
	if in.BotLevel != "" {
		current.BotLevel = in.BotLevel
	}
	if in.WAFMode != "" {
		current.WAFMode = in.WAFMode
	}
	if in.LBPolicy != "" {
		current.LBPolicy = in.LBPolicy
	}
	if in.HealthPath != "" {
		current.HealthPath = in.HealthPath
	}
	if in.HealthExpect != "" {
		current.HealthExpect = in.HealthExpect
	}
	if in.RequestHeaders != nil {
		current.RequestHeaders = in.RequestHeaders
	}
	if in.ResponseHeaders != nil {
		current.ResponseHeaders = in.ResponseHeaders
	}
	if in.TLSMinVersion != "" {
		current.TLSMinVersion = in.TLSMinVersion
	}
	applyProxyNumbers(current, in)
	if msg := validateProxyOptions(in); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if msg := validateUpstreams(in.Upstreams); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if msg := s.checkAuthProvider(in.AuthProviderID); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if msg := requireGateSecret(current.GateMode, current.GateSecret, in.GateSecret); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if in.GateSecret != "" {
		enc, err := s.box.Seal(in.GateSecret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encryption error")
			return
		}
		current.GateSecret = enc
	}
	before := s.snapshotProxy(id)
	if err := s.st.UpdateProxy(current); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update")
		return
	}
	s.saveChildren(id, in)
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.auditChange(sess.Username, "proxy.update", current.Hostname, clientIP(r), "proxy", id, before, s.snapshotProxy(id))
	writeJSON(w, http.StatusOK, current)
}

// applyProxyNumbers copies the optional numeric settings onto a proxy.
func applyProxyNumbers(p *model.Proxy, in proxyBody) {
	for src, dst := range map[*int]*int{
		in.HealthInterval: &p.HealthInterval, in.HealthFailAfter: &p.HealthFailAfter,
		in.MaxInflight: &p.MaxInflight, in.MaxInflightPerClient: &p.MaxInflightPerClient,
		in.UpstreamTimeout: &p.UpstreamTimeout, in.Retries: &p.Retries,
	} {
		if src != nil {
			*dst = *src
		}
	}
}

// validateHeaderOps rejects rewrites that would break framing or the request
// target; a rule that cannot be applied safely is refused at save time.
func validateHeaderOps(ops []model.HeaderOp) string {
	if len(ops) > 50 {
		return "at most 50 rules are allowed"
	}
	forbidden := map[string]bool{
		"host": true, "content-length": true, "transfer-encoding": true,
		"connection": true, "keep-alive": true, "upgrade": true,
	}
	for _, op := range ops {
		action := strings.ToLower(strings.TrimSpace(op.Action))
		switch action {
		case "set", "add", "remove":
		default:
			return "action must be set, add or remove"
		}
		name := strings.TrimSpace(op.Name)
		if !httpgutsToken(name) {
			return "invalid header name"
		}
		if forbidden[strings.ToLower(name)] {
			return name + " cannot be rewritten"
		}
		if action != "remove" && strings.TrimSpace(op.Value) == "" {
			return "a value is required for " + name
		}
	}
	return ""
}

// httpgutsToken reports whether s is an RFC 9110 token, which is the only
// shape a header name may take.
func httpgutsToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
		if !ok {
			return false
		}
	}
	return true
}

func validLBPolicy(policy string) bool {
	switch policy {
	case proxy.LBWeightedRR, proxy.LBLeastConn, proxy.LBLeastLatency, proxy.LBIPHash, proxy.LBStickyCookie:
		return true
	}
	return false
}

// validHealthExpect accepts "200", "200-399" and comma-separated lists of those.
func validHealthExpect(s string) bool {
	if strings.TrimSpace(s) == "" {
		return true
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		lo, hi := part, part
		if i := strings.IndexByte(part, '-'); i >= 0 {
			lo, hi = part[:i], part[i+1:]
		}
		a, err1 := strconv.Atoi(strings.TrimSpace(lo))
		b, err2 := strconv.Atoi(strings.TrimSpace(hi))
		if err1 != nil || err2 != nil || a < 100 || b > 599 || a > b {
			return false
		}
	}
	return true
}

func validateProxyOptions(in proxyBody) string {
	if in.TLSMinVersion != "" && in.TLSMinVersion != "1.2" && in.TLSMinVersion != "1.3" {
		return "the minimum TLS version must be 1.2 or 1.3"
	}
	if in.LBPolicy != "" && !validLBPolicy(in.LBPolicy) {
		return "invalid balancing policy"
	}
	if in.HealthPath != "" && !strings.HasPrefix(in.HealthPath, "/") {
		return "the health path must start with /"
	}
	if !validHealthExpect(in.HealthExpect) {
		return "invalid health status expectation"
	}
	if in.HealthInterval != nil && (*in.HealthInterval < 0 || *in.HealthInterval > 3600) {
		return "the health interval must be between 0 and 3600 seconds"
	}
	if in.HealthFailAfter != nil && (*in.HealthFailAfter < 0 || *in.HealthFailAfter > 20) {
		return "the health failure threshold must be between 0 and 20"
	}
	if in.MaxInflight != nil && (*in.MaxInflight < 0 || *in.MaxInflight > 100000) {
		return "the site request budget must be between 0 and 100000"
	}
	if in.MaxInflightPerClient != nil && (*in.MaxInflightPerClient < 0 || *in.MaxInflightPerClient > 10000) {
		return "the per-client request budget must be between 0 and 10000"
	}
	if in.UpstreamTimeout != nil && (*in.UpstreamTimeout < 0 || *in.UpstreamTimeout > 3600) {
		return "the upstream timeout must be between 0 and 3600 seconds"
	}
	if in.Retries != nil && (*in.Retries < 0 || *in.Retries > 5) {
		return "the retry count must be between 0 and 5"
	}
	if msg := validateHeaderOps(in.RequestHeaders); msg != "" {
		return "request header rules: " + msg
	}
	if msg := validateHeaderOps(in.ResponseHeaders); msg != "" {
		return "response header rules: " + msg
	}
	if in.GateMode != "" && !gateModes[in.GateMode] {
		return "invalid gate mode"
	}
	if in.GateMode == "forward_auth" && in.AuthProviderID == nil {
		return "choose an identity provider for the forward-auth gate"
	}
	if in.WAFMode != "" && !validWAFMode(in.WAFMode) {
		return "invalid WAF mode"
	}
	if in.BotLevel != "" && in.BotLevel != "off" && in.BotLevel != "light" && in.BotLevel != "standard" && in.BotLevel != "aggressive" {
		return "invalid bot level"
	}
	if in.Fingerprint != "" && in.Fingerprint != "strict" && in.Fingerprint != "minimal" {
		return "invalid fingerprint mode"
	}
	return ""
}

// validateUpstreams rejects malformed targets and cloud metadata endpoints, so
// a mistaken or malicious upstream cannot turn the proxy into an SSRF pivot.
func validateUpstreams(ups []upstreamBody) string {
	for _, u := range ups {
		raw := strings.TrimSpace(u.URL)
		if raw == "" {
			continue
		}
		if err := urlguard.Check(raw, urlguard.Upstream); err != nil {
			return "upstream: " + err.Error() + ": " + raw
		}
	}
	return ""
}

// gateModes is the set of accepted access-gate modes.
// checkAuthProvider stops a proxy from pointing at a provider that no longer
// exists, which would leave the site failing closed with no obvious cause.
func (s *Server) checkAuthProvider(id *int64) string {
	if id == nil {
		return ""
	}
	if _, err := s.st.GetAuthProvider(*id); err != nil {
		return "unknown identity provider"
	}
	return ""
}

var gateModes = map[string]bool{"off": true, "passphrase": true, "accounts": true, "accounts_totp": true, "forward_auth": true}

func validWAFMode(mode string) bool {
	return mode == "inherit" || mode == "off" || mode == "detect" || mode == "block"
}

// requireGateSecret refuses to enable the shared-passphrase gate without a
// credential. Otherwise the proxy would serve a login page that no visitor can
// ever satisfy, and the GUI reports the gate as working.
func requireGateSecret(mode, existing, provided string) string {
	if mode != "passphrase" {
		return ""
	}
	if strings.TrimSpace(existing) == "" && strings.TrimSpace(provided) == "" {
		return "a passphrase is required to enable passphrase gate mode"
	}
	return ""
}

func (s *Server) saveChildren(proxyID int64, in proxyBody) {
	ups := make([]model.Upstream, 0, len(in.Upstreams))
	for _, u := range in.Upstreams {
		u.URL = strings.TrimSpace(u.URL)
		if u.URL == "" {
			continue
		}
		w := u.Weight
		if w <= 0 {
			w = 1
		}
		enabled := true
		if u.Enabled != nil {
			enabled = *u.Enabled
		}
		if u.MaxConns < 0 {
			u.MaxConns = 0
		}
		ups = append(ups, model.Upstream{ProxyID: proxyID, URL: u.URL, Weight: w, Enabled: enabled, MaxConns: u.MaxConns})
	}
	_ = s.st.ReplaceUpstreams(proxyID, ups)
	_ = s.st.ReplaceRoutes(proxyID, in.Routes)
	if in.GateUsers != nil {
		_ = s.st.SetGateACL(proxyID, in.GateUsers)
	}
}

func (s *Server) deleteProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	p, _ := s.st.GetProxy(id)
	before := s.snapshotProxy(id)
	if err := s.st.DeleteProxy(id); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot delete")
		return
	}
	s.reload(r.Context())
	sess := sessionFrom(r)
	name := ""
	if p != nil {
		name = p.Hostname
	}
	s.auditChange(sess.Username, "proxy.delete", name, clientIP(r), "proxy", id, before, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) validateHostname(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if !validHostname(host) {
		return "hostname is not valid"
	}
	base, _ := s.st.GetSetting("base_domain")
	if base == "" {
		return "base domain is not configured"
	}
	if host == base {
		return "the apex domain is reserved and blackholed; use a subdomain"
	}
	if !strings.HasSuffix(host, "."+base) {
		return "hostname must be a subdomain of " + base
	}
	label := strings.TrimSuffix(host, "."+base)
	if strings.Contains(label, ".") {
		return "use a single-label subdomain"
	}
	if raw, _ := s.st.GetSetting("decoy_hosts"); raw != "" {
		for _, d := range strings.Split(raw, ",") {
			if strings.EqualFold(strings.TrimSpace(d), host) {
				return "hostname is configured as a decoy"
			}
		}
	}
	return ""
}

func (s *Server) revokeGate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	_ = s.st.DeleteProxyGateSessions(id)
	sess := sessionFrom(r)
	detail := strconv.FormatInt(id, 10)
	if p, err := s.st.GetProxy(id); err == nil && p != nil {
		detail = p.Hostname
	}
	s.st.AddAudit(sess.Username, "proxy.gate_revoke", detail, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// A server built without the runtime engines (unit tests) has nothing to reload.
func (s *Server) reload(ctx context.Context) {
	if s.policy != nil {
		if err := s.policy.Reload(); err != nil {
			s.log.Error("reload policies", "err", err)
		}
	}
	if s.proxy != nil {
		if err := s.proxy.Reload(ctx); err != nil {
			s.log.Error("reload proxy routes", "err", err)
		}
	}
}

// ---------- profiles ----------

func (s *Server) listProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.st.ListProfiles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, profiles)
}

func (s *Server) updateProfile(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	p, err := s.st.GetProfile(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	var in model.Profile
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if in.Mode != "" {
		if !validWAFMode(in.Mode) {
			writeError(w, http.StatusBadRequest, "invalid WAF mode")
			return
		}
		p.Mode = in.Mode
	}
	if in.Paranoia >= 1 && in.Paranoia <= 4 {
		p.Paranoia = in.Paranoia
	}
	if in.Anomaly > 0 {
		p.Anomaly = in.Anomaly
	}
	if in.Responses != "" {
		p.Responses = in.Responses
	}
	if in.AllowedMethods != "" {
		p.AllowedMethods = in.AllowedMethods
	}
	if in.MaxBody > 0 {
		p.MaxBody = in.MaxBody
	}
	p.Exceptions = in.Exceptions
	if msg := validateProfileLimits(in); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	p.MaxResponse, p.LoginPaths, p.LoginRPS = in.MaxResponse, in.LoginPaths, in.LoginRPS
	p.LoginBurst, p.AdminPaths, p.AdminIPs = in.LoginBurst, in.AdminPaths, in.AdminIPs
	before := s.snapshotProfile(p.ID)
	if err := s.st.UpdateProfile(p); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update")
		return
	}
	// A server built without the engines (unit tests) has nothing to reload.
	if s.policy != nil {
		if err := s.policy.ReloadWAF(); err != nil {
			s.log.Error("reload WAF profiles", "err", err)
		}
	}
	sess := sessionFrom(r)
	s.auditChange(sess.Username, "profile.update", p.Name, clientIP(r), "profile", p.ID, before, s.snapshotProfile(p.ID))
	writeJSON(w, http.StatusOK, p)
}

// createProfile adds a CRS profile an admin names and tunes themselves. The
// built-in profiles stay as reference defaults; a custom one starts from the
// same safe values so a new profile never means "no WAF".
func (s *Server) createProfile(w http.ResponseWriter, r *http.Request) {
	var in model.Profile
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 64 {
		writeError(w, http.StatusBadRequest, "a profile name of 1–64 characters is required")
		return
	}
	p := model.Profile{
		Name:           name,
		Mode:           "block",
		Responses:      "off",
		Paranoia:       1,
		Anomaly:        5,
		AllowedMethods: "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:        131072,
	}
	if in.Mode != "" {
		if !validWAFMode(in.Mode) {
			writeError(w, http.StatusBadRequest, "invalid WAF mode")
			return
		}
		p.Mode = in.Mode
	}
	if in.Paranoia >= 1 && in.Paranoia <= 4 {
		p.Paranoia = in.Paranoia
	}
	if in.Anomaly > 0 && in.Anomaly <= 100 {
		p.Anomaly = in.Anomaly
	}
	if in.Responses != "" {
		p.Responses = in.Responses
	}
	if strings.TrimSpace(in.AllowedMethods) != "" {
		p.AllowedMethods = strings.TrimSpace(in.AllowedMethods)
	}
	if in.MaxBody >= 1024 && in.MaxBody <= 8388608 {
		p.MaxBody = in.MaxBody
	}
	p.Exceptions = in.Exceptions
	if msg := validateProfileLimits(in); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	p.MaxResponse, p.LoginPaths, p.LoginRPS = in.MaxResponse, in.LoginPaths, in.LoginRPS
	p.LoginBurst, p.AdminPaths, p.AdminIPs = in.LoginBurst, in.AdminPaths, in.AdminIPs
	if err := s.st.CreateProfile(&p); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			writeError(w, http.StatusConflict, "a profile with that name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "cannot create profile")
		return
	}
	if s.policy != nil {
		if err := s.policy.ReloadWAF(); err != nil {
			s.log.Error("reload WAF profiles", "err", err)
		}
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "profile.create", p.Name, clientIP(r))
	writeJSON(w, http.StatusCreated, p)
}

// validateProfileLimits rejects a record that would not do what it says. A
// mistyped CIDR is refused rather than silently ignored, because ignoring it
// would leave an admin path open to everyone.
func validateProfileLimits(in model.Profile) string {
	switch in.Responses {
	case "", "off", "flag", "block":
	default:
		return "responses must be off, flag or block"
	}
	if in.MaxResponse < 0 || in.MaxResponse > 1<<32 {
		return "the response ceiling must be between 0 (unlimited) and 4 GiB"
	}
	if in.LoginRPS < 0 || in.LoginRPS > 1000 {
		return "login rate must be between 0 (off) and 1000 requests per second"
	}
	if in.LoginBurst < 0 || in.LoginBurst > 10000 {
		return "login burst must be between 0 and 10000"
	}
	if strings.TrimSpace(in.LoginPaths) != "" && in.LoginRPS == 0 {
		return "set a login rate when login paths are listed"
	}
	for _, part := range strings.Split(in.AdminIPs, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, err := netip.ParsePrefix(part); err != nil {
			if _, err := netip.ParseAddr(part); err != nil {
				return "invalid address or CIDR in the admin allowlist: " + part
			}
		}
	}
	return ""
}

func (s *Server) listPresets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, preset.All())
}

func (s *Server) deleteProfile(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	p, err := s.st.GetProfile(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if p.Builtin {
		writeError(w, http.StatusConflict, "built-in profiles cannot be deleted")
		return
	}
	inUse, err := s.st.ProfileInUse(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if inUse > 0 {
		noun := "proxies"
		if inUse == 1 {
			noun = "proxy"
		}
		writeError(w, http.StatusConflict,
			fmt.Sprintf("%s is selected by %d %s; assign another profile first", p.Name, inUse, noun))
		return
	}
	before := s.snapshotProfile(id)
	if err := s.st.DeleteProfile(id); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot delete profile")
		return
	}
	if s.policy != nil {
		if err := s.policy.ReloadWAF(); err != nil {
			s.log.Error("reload WAF profiles", "err", err)
		}
	}
	sess := sessionFrom(r)
	s.auditChange(sess.Username, "profile.delete", p.Name, clientIP(r), "profile", id, before, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------- policies ----------

var policyKinds = map[string]bool{
	model.PolicyIPWhitelist: true, model.PolicyIPBlacklist: true, model.PolicyCountryWhitelist: true,
	model.PolicyCountryBlacklist: true, model.PolicyASNBlock: true,
	model.PolicyDecoy: true, "rate_limit": true,
}

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListPolicies()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) {
	var in model.Policy
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if !policyKinds[in.Kind] {
		writeError(w, http.StatusBadRequest, "unknown policy kind")
		return
	}
	if strings.TrimSpace(in.Value) == "" {
		writeError(w, http.StatusBadRequest, "value is required")
		return
	}
	if msg := validatePolicyValue(in.Kind, in.Value); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if in.Scope == "" {
		in.Scope = "global"
	}
	if in.Scope == "proxy" && in.ProxyID == nil {
		writeError(w, http.StatusBadRequest, "proxy scope requires proxy_id")
		return
	}
	in.Enabled = true
	id, err := s.st.CreatePolicy(&in)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot create")
		return
	}
	in.ID = id
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "policy.create", in.Kind+" "+in.Value, clientIP(r))
	writeJSON(w, http.StatusCreated, in)
}

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	// enabled and priority are optional on update: an omitted field keeps the
	// stored value instead of silently switching the list off or resetting it.
	var body struct {
		Scope    string `json:"scope"`
		ProxyID  *int64 `json:"proxy_id"`
		Kind     string `json:"kind"`
		Value    string `json:"value"`
		Action   string `json:"action"`
		Priority *int   `json:"priority"`
		Enabled  *bool  `json:"enabled"`
		Note     string `json:"note"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	current, err := s.st.GetPolicy(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	in := *current
	in.Scope, in.ProxyID, in.Kind = body.Scope, body.ProxyID, body.Kind
	in.Value, in.Action, in.Note = body.Value, body.Action, body.Note
	if body.Priority != nil {
		in.Priority = *body.Priority
	}
	if body.Enabled != nil {
		in.Enabled = *body.Enabled
	}
	if in.Scope == "" {
		in.Scope = "global"
	}
	if !policyKinds[in.Kind] {
		writeError(w, http.StatusBadRequest, "unknown policy kind")
		return
	}
	if strings.TrimSpace(in.Value) == "" {
		writeError(w, http.StatusBadRequest, "value is required")
		return
	}
	if in.Scope == "proxy" && in.ProxyID == nil {
		writeError(w, http.StatusBadRequest, "proxy scope requires proxy_id")
		return
	}
	if msg := validatePolicyValue(in.Kind, in.Value); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	before := s.snapshotPolicy(in.ID)
	if err := s.st.UpdatePolicy(&in); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update")
		return
	}
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.auditChange(sess.Username, "policy.update", in.Kind+" "+in.Value, clientIP(r), "policy", in.ID, before, s.snapshotPolicy(in.ID))
	writeJSON(w, http.StatusOK, in)
}

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	before := s.snapshotPolicy(id)
	if err := s.st.DeletePolicy(id); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot delete")
		return
	}
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.auditChange(sess.Username, "policy.delete", strconv.FormatInt(id, 10), clientIP(r), "policy", id, before, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------- bans ----------

func (s *Server) listBans(w http.ResponseWriter, r *http.Request) {
	all := r.URL.Query().Get("all") == "1"
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	// Mirror the store's own normalisation so the flag describes the limit that
	// was actually applied, not just whether the caller passed one.
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	list, err := s.st.ListBansPage(all, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	active, reason := s.bans.KernelStatus()
	total, err := s.st.CountBans(all)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"bans": list, "active": s.bans.Count(), "limited": len(list) == limit && total > limit,
		"total":  total,
		"kernel": map[string]any{"active": active, "reason": reason},
	})
}

type banBody struct {
	CIDR      string `json:"cidr"`
	Reason    string `json:"reason"`
	Permanent bool   `json:"permanent"`
	TTL       int    `json:"ttl_seconds"`
}

func (s *Server) createBan(w http.ResponseWriter, r *http.Request) {
	var in banBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	in.CIDR = strings.TrimSpace(in.CIDR)
	if in.CIDR == "" {
		writeError(w, http.StatusBadRequest, "cidr is required")
		return
	}
	p, err := netip.ParsePrefix(in.CIDR)
	if err != nil {
		a, aerr := netip.ParseAddr(in.CIDR)
		if aerr != nil {
			writeError(w, http.StatusBadRequest, "invalid IP or CIDR")
			return
		}
		p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
	}
	if strings.TrimSpace(in.Reason) == "" {
		writeError(w, http.StatusBadRequest, "a reason is required")
		return
	}
	ttl := time.Duration(0)
	if !in.Permanent {
		// A temporary ban lasts at most a day: the point is a cool-down, and an
		// unbounded TTL turns the list into a second permanent list. Refuse the
		// request instead of silently shortening what the operator asked for.
		max := int(ban.MaxTempTTL / time.Second)
		if in.TTL <= 0 {
			in.TTL = max
		}
		if in.TTL > max {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("a temporary ban lasts at most %d seconds (24 hours); make it permanent to keep it", max))
			return
		}
		ttl = time.Duration(in.TTL) * time.Second
	}
	sess := sessionFrom(r)
	rec, err := s.bans.Add(p.String(), in.Reason, "manual", sess.Username, ttl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot create ban")
		return
	}
	s.st.AddAudit(sess.Username, "ban.create", rec.CIDR+" "+in.Reason, clientIP(r))
	// Return the stored row, not the engine's Go struct: GET /api/bans serves
	// model.Ban with lowercase JSON keys, and a caller should see the same shape
	// (including the new id) whichever endpoint created it.
	created, err := s.st.BanByCIDR(rec.CIDR)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot load the created ban")
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) deleteBan(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	b, err := s.bans.ByID(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if err := s.bans.Remove(b.CIDR); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot remove ban")
		return
	}
	sess := sessionFrom(r)
	s.auditChange(sess.Username, "ban.delete", b.CIDR+" "+b.Reason, clientIP(r), "ban", b.ID, snapshotJSON(b), nil)
}

func (s *Server) promoteBan(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	b, err := s.bans.ByID(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if err := s.bans.Promote(b.CIDR); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot promote")
		return
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "ban.promote", b.CIDR, clientIP(r))
}

// bulkBans promotes or lifts the selected bans in one call. The UI sends the
// rows the admin ticked, so a select-all is one audited operation instead of
// hundreds of requests.
func (s *Server) bulkBans(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDs    []int64 `json:"ids"`
		Action string  `json:"action"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if len(in.IDs) == 0 {
		writeError(w, http.StatusBadRequest, "select at least one ban")
		return
	}
	if len(in.IDs) > 5000 {
		writeError(w, http.StatusBadRequest, "too many bans in one request")
		return
	}
	if in.Action != "permanent" && in.Action != "temp" && in.Action != "remove" {
		writeError(w, http.StatusBadRequest, "action must be permanent, temp or remove")
		return
	}

	seen := make(map[int64]bool, len(in.IDs))
	updated, skipped := 0, 0
	for _, id := range in.IDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		b, err := s.bans.ByID(id)
		if errors.Is(err, store.ErrNotFound) {
			skipped++
			continue
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		switch in.Action {
		case "permanent":
			if b.Permanent {
				skipped++
				continue
			}
			if err := s.bans.Promote(b.CIDR); err != nil {
				skipped++
				continue
			}
		case "temp":
			// A permanent ban moved back is a 24-hour cool-down, the longest a
			// temporary ban can be; the row keeps its reason and history.
			if !b.Permanent {
				skipped++
				continue
			}
			if err := s.bans.Demote(b.CIDR, ban.MaxTempTTL); err != nil {
				skipped++
				continue
			}
		case "remove":
			if err := s.bans.Remove(b.CIDR); err != nil {
				skipped++
				continue
			}
		}
		updated++
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "ban.bulk", fmt.Sprintf("%s %d ban(s)", in.Action, updated), clientIP(r))
	writeJSON(w, http.StatusOK, map[string]int{"updated": updated, "skipped": skipped})
}

// ---------- feeds ----------

func (s *Server) listFeeds(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListFeeds()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	status := s.feeds.Status()
	writeJSON(w, http.StatusOK, map[string]any{"feeds": list, "status": status, "total": s.feeds.Total()})
}

func (s *Server) createFeed(w http.ResponseWriter, r *http.Request) {
	var in model.Feed
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if strings.TrimSpace(in.Name) == "" || !validFeedURL(in.URL) {
		writeError(w, http.StatusBadRequest, "name and an http(s) url are required")
		return
	}
	// A local path is only ever assigned by uploadFeed. Ignoring these fields
	// stops a crafted request from pointing the reader at an arbitrary file.
	in.Enabled = true
	in.Local = false
	in.LocalPath = ""
	in.Filename = ""
	id, err := s.st.CreateFeed(&in)
	if err != nil {
		writeError(w, http.StatusConflict, "feed already exists")
		return
	}
	go s.feeds.Refresh(context.Background(), id)
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "feed.create", in.Name, clientIP(r))
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (s *Server) updateFeed(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in model.Feed
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	in.ID = id
	current, err := s.st.FeedByID(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "feed not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if current.Local {
		// Uploaded lists are a blocklist; neither the UI nor a crafted request
		// may downgrade them to challenge or log-only.
		in.Action = "block"
	}
	if in.IntervalS <= 0 {
		in.IntervalS = 900
	}
	if err := s.st.UpdateFeed(&in); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update")
		return
	}
	go s.feeds.Refresh(context.Background(), id)
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "feed.update", strconv.FormatInt(id, 10), clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

const maxLocalFeedBytes = 10 << 20

// uploadFeed stores a .txt or .csv IP list in the data directory and registers
// it as a local, always-blocking feed. The upload is parsed before it is saved,
// so an empty or malformed file cannot install a feed that silently does
// nothing.
func (s *Server) uploadFeed(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLocalFeedBytes+(1<<20))
	if err := r.ParseMultipartForm(maxLocalFeedBytes + (1 << 20)); err != nil {
		writeError(w, http.StatusBadRequest, "upload a .txt or .csv file up to 10 MB")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()

	filename := filepath.Base(strings.TrimSpace(header.Filename))
	ext := strings.ToLower(filepath.Ext(filename))
	if ext != ".txt" && ext != ".csv" {
		writeError(w, http.StatusBadRequest, "only .txt and .csv files are accepted")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = strings.TrimSuffix(filename, filepath.Ext(filename))
	}
	if name == "" || len(name) > 120 {
		writeError(w, http.StatusBadRequest, "name must be 1-120 characters")
		return
	}

	feedDir := filepath.Join(s.cfg.DataDir, "feeds")
	if err := os.MkdirAll(feedDir, 0o750); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot create feed directory")
		return
	}
	tmp, err := os.CreateTemp(feedDir, ".upload-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot store upload")
		return
	}
	tmpPath := tmp.Name()
	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()

	written, err := io.Copy(tmp, io.LimitReader(file, maxLocalFeedBytes+1))
	if err != nil {
		tmp.Close()
		writeError(w, http.StatusBadRequest, "cannot read upload")
		return
	}
	if written == 0 || written > maxLocalFeedBytes {
		tmp.Close()
		writeError(w, http.StatusBadRequest, "file must be between 1 byte and 10 MB")
		return
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		tmp.Close()
		writeError(w, http.StatusInternalServerError, "cannot read upload")
		return
	}
	var prefixes []netip.Prefix
	if ext == ".csv" {
		prefixes, err = intel.ParseCSV(tmp)
	} else {
		prefixes, err = intel.Parse(tmp)
	}
	tmp.Close()
	if err != nil {
		writeError(w, http.StatusBadRequest, "cannot parse file: "+err.Error())
		return
	}
	if len(prefixes) == 0 {
		writeError(w, http.StatusBadRequest, "no IP addresses or CIDRs found in the file")
		return
	}

	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot allocate feed name")
		return
	}
	localPath := filepath.Join(feedDir, hex.EncodeToString(random)+ext)
	if err := os.Chmod(tmpPath, 0o640); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot secure upload")
		return
	}
	if err := os.Rename(tmpPath, localPath); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot save upload")
		return
	}
	// The rename consumed the temporary path; the saved file now belongs to the
	// feed and must survive this handler.
	tmpPath = ""

	feed := &model.Feed{
		Name: name, Action: "block", IntervalS: 3600, Enabled: true,
		Local: true, Filename: filename, LocalPath: localPath,
	}
	id, err := s.st.CreateFeed(feed)
	if err != nil {
		_ = os.Remove(localPath)
		writeError(w, http.StatusConflict, "a feed with that name already exists")
		return
	}
	go s.feeds.Refresh(context.Background(), id)
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "feed.upload", name+" ("+filename+")", clientIP(r))
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "entries": len(prefixes)})
}

func (s *Server) deleteFeed(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	feed, err := s.st.FeedByID(id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	removed, err := s.st.DeleteFeed(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot delete feed")
		return
	}
	if !removed {
		writeError(w, http.StatusNotFound, "feed not found or built in")
		return
	}
	if feed != nil && feed.LocalPath != "" {
		feedDir := filepath.Join(s.cfg.DataDir, "feeds")
		if rel, err := filepath.Rel(feedDir, feed.LocalPath); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			_ = os.Remove(feed.LocalPath)
		}
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "feed.delete", strconv.FormatInt(id, 10), clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) refreshFeed(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	go s.feeds.Refresh(context.Background(), id)
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "refreshing"})
}

// ---------- certificates ----------

func (s *Server) listCerts(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListCerts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, c := range list {
		out = append(out, s.certs.CertSummary(c))
	}
	creds, err := s.st.ListDNSCredentials()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	configured := make([]string, 0, len(creds))
	for _, c := range creds {
		configured = append(configured, c.Provider)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"certs": out, "providers": acme.Providers, "configured": configured,
	})
}

type certBody struct {
	Domains   string            `json:"domains"`
	Provider  string            `json:"provider"`
	Creds     map[string]string `json:"creds"`
	RenewMode string            `json:"renew_mode"`
	Challenge string            `json:"challenge"`
}

func (s *Server) createCert(w http.ResponseWriter, r *http.Request) {
	var in certBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	in.Domains = strings.TrimSpace(in.Domains)
	if in.Domains == "" {
		writeError(w, http.StatusBadRequest, "domains are required")
		return
	}
	if in.Challenge == "" {
		in.Challenge = model.CertChallengeDNS
	}
	if !model.ValidCertChallenge(in.Challenge) {
		writeError(w, http.StatusBadRequest, "unsupported challenge type")
		return
	}
	// A DNS provider is only needed for DNS-01; the other challenges prove
	// control through the proxy's own listeners.
	if in.Challenge == model.CertChallengeDNS {
		valid := false
		for _, p := range acme.Providers {
			if p == in.Provider {
				valid = true
			}
		}
		if !valid {
			writeError(w, http.StatusBadRequest, "unsupported provider")
			return
		}
	} else {
		in.Provider = in.Challenge
		in.Creds = nil
	}
	if in.RenewMode == "" {
		in.RenewMode = model.CertRenewBeforeExpiry
	}
	if !model.ValidCertRenewMode(in.RenewMode) {
		writeError(w, http.StatusBadRequest, "invalid renewal mode")
		return
	}
	for _, d := range strings.Split(in.Domains, ",") {
		d = strings.TrimSpace(d)
		if strings.HasPrefix(d, "*.") {
			if in.Challenge != model.CertChallengeDNS {
				writeError(w, http.StatusBadRequest, "wildcard names need DNS-01; HTTP-01 and TLS-ALPN-01 cannot validate them")
				return
			}
			d = d[2:]
		}
		if !validHostname(d) {
			writeError(w, http.StatusBadRequest, "invalid domain: "+d)
			return
		}
	}
	if len(in.Creds) > 0 && in.Challenge == model.CertChallengeDNS {
		raw, _ := json.Marshal(in.Creds)
		enc, err := s.box.Seal(string(raw))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encryption error")
			return
		}
		if err := s.st.UpsertDNSCredential(in.Provider, in.Provider, enc); err != nil {
			writeError(w, http.StatusInternalServerError, "cannot store credentials")
			return
		}
	}
	c := &model.Cert{
		Domains: in.Domains, Provider: in.Provider, Status: "pending",
		Wildcard: strings.Contains(in.Domains, "*."), RenewMode: in.RenewMode,
		Challenge: in.Challenge,
	}
	id, err := s.st.SaveCert(c)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot create certificate")
		return
	}
	go func() {
		if err := s.certs.Issue(id); err != nil {
			s.log.Warn("certificate issuance failed", "id", id, "err", err)
		}
	}()
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "cert.create", in.Domains, clientIP(r))
	writeJSON(w, http.StatusAccepted, map[string]any{"id": id, "status": "pending"})
}

// issueInternalCert signs a certificate from the local root for an install
// without a public domain.
func (s *Server) issueInternalCert(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domains []string `json:"domains"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	hosts := make([]string, 0, len(in.Domains))
	for _, raw := range in.Domains {
		host := strings.ToLower(strings.TrimSpace(raw))
		if host == "" {
			continue
		}
		base := strings.TrimPrefix(host, "*.")
		if !validHostname(base) {
			writeError(w, http.StatusBadRequest, "invalid domain: "+host)
			return
		}
		hosts = append(hosts, host)
	}
	if len(hosts) == 0 || len(hosts) > 32 {
		writeError(w, http.StatusBadRequest, "name between 1 and 32 domains")
		return
	}
	auth, err := internalca.Load(s.cfg.DataDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "the internal CA is unavailable: "+err.Error())
		return
	}
	certPEM, keyPEM, notBefore, notAfter, err := auth.Issue(hosts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot issue the certificate")
		return
	}
	c := &model.Cert{
		Domains: strings.Join(hosts, ","), Provider: "internal", Status: "issued",
		Source: model.CertSourceInternal, CertPEM: certPEM, KeyPEM: keyPEM,
		IssuedAt: &notBefore, ExpiresAt: &notAfter,
		Wildcard:  strings.Contains(strings.Join(hosts, ","), "*."),
		RenewMode: model.CertRenewBeforeExpiry, Challenge: "internal",
	}
	id, err := s.st.SaveCert(c)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot store the certificate")
		return
	}
	if s.certs != nil {
		_ = s.certs.Load()
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "cert.internal", c.Domains, clientIP(r))
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "domains": c.Domains, "expires_at": notAfter})
}

// internalCARoot serves the trust anchor clients install to accept internal
// certificates.
func (s *Server) internalCARoot(w http.ResponseWriter, r *http.Request) {
	auth, err := internalca.Load(s.cfg.DataDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "the internal CA is unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="wafproxy-internal-ca.pem"`)
	_, _ = w.Write(auth.RootPEM())
}

// uploadCert stores an operator-supplied certificate and key. The pair must
// parse and match, and the names come from the certificate itself so the
// inventory cannot disagree with what is served.
func (s *Server) uploadCert(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if len(in.CertPEM) > 256<<10 || len(in.KeyPEM) > 256<<10 {
		writeError(w, http.StatusBadRequest, "the certificate or key is too large")
		return
	}
	pair, err := tls.X509KeyPair([]byte(in.CertPEM), []byte(in.KeyPEM))
	if err != nil {
		writeError(w, http.StatusBadRequest, "the certificate and key do not match")
		return
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		writeError(w, http.StatusBadRequest, "the certificate cannot be parsed")
		return
	}
	names := leaf.DNSNames
	if len(names) == 0 && leaf.Subject.CommonName != "" {
		names = []string{leaf.Subject.CommonName}
	}
	if len(names) == 0 {
		writeError(w, http.StatusBadRequest, "the certificate names no hostname")
		return
	}
	for _, name := range names {
		base := strings.TrimPrefix(strings.ToLower(name), "*.")
		if !validHostname(base) {
			writeError(w, http.StatusBadRequest, "invalid domain in the certificate: "+name)
			return
		}
	}
	if time.Now().After(leaf.NotAfter) {
		writeError(w, http.StatusBadRequest, "the certificate has expired")
		return
	}
	c := &model.Cert{
		Domains: strings.Join(names, ","), Provider: "upload", Status: "issued",
		Source: model.CertSourceUploaded, CertPEM: []byte(in.CertPEM), KeyPEM: []byte(in.KeyPEM),
		IssuedAt: &leaf.NotBefore, ExpiresAt: &leaf.NotAfter,
		Wildcard: strings.Contains(strings.Join(names, ","), "*."), RenewMode: model.CertRenewBeforeExpiry,
		Challenge: "upload",
	}
	id, err := s.st.SaveCert(c)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot store the certificate")
		return
	}
	if s.certs != nil {
		if err := s.certs.Load(); err != nil {
			s.log.Warn("reload certificates after upload", "err", err)
		}
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "cert.upload", c.Domains, clientIP(r))
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "domains": c.Domains, "expires_at": c.ExpiresAt})
}

func (s *Server) updateCert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in struct {
		RenewMode string `json:"renew_mode"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if !model.ValidCertRenewMode(in.RenewMode) {
		writeError(w, http.StatusBadRequest, "invalid renewal mode")
		return
	}
	if err := s.st.SetCertRenewMode(id, in.RenewMode); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update certificate")
		return
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "cert.renew_policy", strconv.FormatInt(id, 10)+" "+in.RenewMode, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "renew_mode": in.RenewMode})
}

func (s *Server) renewCert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	go func() {
		if err := s.certs.Issue(id); err != nil {
			s.log.Warn("certificate renewal failed", "id", id, "err", err)
		}
	}()
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "cert.renew", strconv.FormatInt(id, 10), clientIP(r))
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "renewing"})
}

func (s *Server) revokeCert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	cert, err := s.st.GetCert(id)
	if err != nil || cert == nil {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}
	if cert.Source == model.CertSourceACME {
		if s.certs == nil {
			writeError(w, http.StatusServiceUnavailable, "certificate manager unavailable")
			return
		}
		if err := s.certs.Revoke(id); err != nil {
			writeError(w, http.StatusBadGateway, "the CA refused revocation: "+err.Error())
			return
		}
	}
	if err := s.st.DeleteCert(id); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot delete")
		return
	}
	if s.certs != nil {
		_ = s.certs.Load()
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "cert.revoke", cert.Domains, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) deleteCert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	domains := strconv.FormatInt(id, 10)
	if c, err := s.st.GetCert(id); err == nil && c != nil {
		domains = c.Domains
	}
	if err := s.st.DeleteCert(id); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot delete")
		return
	}
	_ = s.certs.Load()
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "cert.delete", domains, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------- observability ----------

func (s *Server) getMetrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.metricsSnapshot())
}

// metricsSnapshot is the console's view of the counters: the process metrics
// plus the proxy's request budget, which lives on the proxy server. Both the
// polled and the streamed payload come from here, so the dashboard cannot show
// one and not the other.
func (s *Server) metricsSnapshot() metrics.Snapshot {
	snap := s.metrics.Snapshot()
	if s.proxy != nil {
		snap.Inflight, snap.MaxInflight, snap.Shed = s.proxy.Capacity()
	}
	return snap
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	f := eventFilterFromQuery(r.URL.Query())
	events, total, err := s.st.QueryEvents(f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "total": total})
}

func (s *Server) getGlobe(w http.ResponseWriter, r *http.Request) {
	points, err := s.st.Globe(globeSince(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, points)
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("format") == "csv" {
		// The export covers the whole table, not the console's 200-row view.
		list, err := s.st.ListAuditAll()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="audit.csv"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"id", "time", "user", "action", "detail", "ip"})
		for _, e := range list {
			_ = cw.Write([]string{strconv.FormatInt(e.ID, 10), e.TS.Format(time.RFC3339), e.User, e.Action, e.Detail, e.IP})
		}
		cw.Flush()
		return
	}
	list, err := s.st.ListAudit(200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// verifyAudit reports the first row or tail that no longer matches the chain.
func (s *Server) verifyAudit(w http.ResponseWriter, _ *http.Request) {
	checked, problem, err := s.st.VerifyAuditChain()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	resp := map[string]any{"ok": problem == "", "checked": checked}
	if problem != "" {
		resp["problem"] = problem
	}
	writeJSON(w, http.StatusOK, resp)
}

func bearerAuth(r *http.Request) string {
	parts := strings.SplitN(strings.TrimSpace(r.Header.Get("Authorization")), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// prometheusMetrics serves the per-proxy counters in the text exposition format.
// It sits outside the console session, so the scraper sends the bearer token from
// WAFPROXY_METRICS_TOKEN; without one the endpoint stays closed.
func (s *Server) prometheusMetrics(w http.ResponseWriter, r *http.Request) {
	if s.cfg.MetricsToken == "" {
		writeError(w, http.StatusForbidden, "metrics are closed; set WAFPROXY_METRICS_TOKEN")
		return
	}
	if subtle.ConstantTimeCompare([]byte(bearerAuth(r)), []byte(s.cfg.MetricsToken)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="wafproxy-metrics"`)
		writeError(w, http.StatusUnauthorized, "a metrics bearer token is required")
		return
	}
	snap := s.metrics.Snapshot()
	ids := make([]string, 0, len(snap.Proxies))
	for id := range snap.Proxies {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var b strings.Builder
	for _, m := range []struct {
		name, help string
		val        func(*metrics.Counters) int64
	}{
		{"wafproxy_requests_total", "Requests handled, by proxy.", func(c *metrics.Counters) int64 { return c.Requests }},
		{"wafproxy_blocked_total", "Requests blocked, by proxy.", func(c *metrics.Counters) int64 { return c.Blocked }},
		{"wafproxy_bytes_in_total", "Request bytes read, by proxy.", func(c *metrics.Counters) int64 { return c.BytesIn }},
		{"wafproxy_bytes_out_total", "Response bytes written, by proxy.", func(c *metrics.Counters) int64 { return c.BytesOut }},
	} {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", m.name, m.help, m.name)
		for _, id := range ids {
			fmt.Fprintf(&b, "%s{proxy=%q} %d\n", m.name, id, m.val(snap.Proxies[id]))
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = io.WriteString(w, b.String())
}

// ---------- notifications ----------

func (s *Server) getNotifications(w http.ResponseWriter, r *http.Request) {
	settings, err := s.notify.Settings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	recent, _ := s.st.RecentAlerts(50)
	// A row keeps the kind it was queued with, which may predate the class it
	// now routes as (CrowdSec bans were once stored as a plain ban), so show
	// both and whether that class is currently muted.
	type recentRow struct {
		model.Alert
		Class string `json:"class"`
		Muted bool   `json:"muted"`
	}
	rows := make([]recentRow, 0, len(recent))
	for _, a := range recent {
		class := notify.RouteClass(a)
		rows = append(rows, recentRow{Alert: a, Class: class, Muted: !s.notify.EventEnabled(class)})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings": settings, "channels": s.notify.Channels(), "recent": rows,
		"event_kinds": notify.EventKinds,
	})
}

func (s *Server) putNotifications(w http.ResponseWriter, r *http.Request) {
	var in map[string]string
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if err := s.notify.Update(in); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot save")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) testNotification(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Channel string `json:"channel"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	channel := strings.ToLower(strings.TrimSpace(in.Channel))
	switch channel {
	case "telegram", "email", "webhook":
	default:
		writeError(w, http.StatusBadRequest, "unknown channel")
		return
	}
	if err := s.notify.Test(channel); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

// ---------- gate users ----------

func (s *Server) listGateUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.st.ListGateUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) createGateUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		TOTPEnabled bool   `json:"totp_enabled"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if in.Username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	secret := ""
	enc := ""
	if in.TOTPEnabled {
		secret, err = auth.NewTOTPSecret()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "cannot generate secret")
			return
		}
		enc, err = s.box.Seal(secret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encryption error")
			return
		}
	}
	id, err := s.st.CreateGateUser(in.Username, hash, enc, in.TOTPEnabled)
	if err != nil {
		writeError(w, http.StatusConflict, "username already exists")
		return
	}
	resp := map[string]any{"id": id, "username": in.Username}
	if in.TOTPEnabled {
		resp["otpauth_url"] = auth.OTPAuthURL("WAF-Proxy", in.Username, secret)
		resp["totp_secret"] = secret
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "gate_user.create", in.Username, clientIP(r))
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) updateGateUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in struct {
		Password    string `json:"password"`
		TOTPEnabled *bool  `json:"totp_enabled"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	users, _ := s.st.ListGateUsers()
	var target *model.GateUser
	for i := range users {
		if users[i].ID == id {
			target = &users[i]
		}
	}
	if target == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	hash := target.PasswordHash
	if in.Password != "" {
		hash, err = auth.HashPassword(in.Password)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	secret := target.TOTPSecret
	enabled := target.TOTPEnabled
	// "No secret yet" is judged by decrypting, not by the stored string being
	// empty: a row can hold a sealed empty value from before TOTP was enabled.
	hasSecret := false
	if plain, derr := s.box.Open(secret); derr == nil && plain != "" {
		hasSecret = true
	}
	// A secret generated here has never been shown to the account holder, so
	// the response returns it once; without that the account would be locked
	// behind a code nobody can produce.
	fresh := ""
	if in.TOTPEnabled != nil {
		enabled = *in.TOTPEnabled
		if enabled && !hasSecret {
			plain, err := auth.NewTOTPSecret()
			if err != nil {
				writeError(w, http.StatusInternalServerError, "cannot generate secret")
				return
			}
			secret, err = s.box.Seal(plain)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "encryption error")
				return
			}
			fresh = plain
		}
	}
	if err := s.st.UpdateGateUser(id, hash, secret, enabled); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update")
		return
	}
	if in.Password != "" {
		// A credential change must end the sessions opened with the old one.
		_ = s.st.DeleteGateSessionsFor(target.Username)
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "gate_user.update", target.Username, clientIP(r))
	resp := map[string]any{"status": "ok"}
	if fresh != "" {
		resp["otpauth_url"] = auth.OTPAuthURL("WAF-Proxy", target.Username, fresh)
		resp["totp_secret"] = fresh
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) deleteGateUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.st.DeleteGateUser(id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot delete")
		return
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "gate_user.delete", strconv.FormatInt(id, 10), clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------- live stream ----------

func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	globeTick := time.NewTicker(3 * time.Second)
	defer globeTick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			data, err := json.Marshal(s.metricsSnapshot())
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: metrics\ndata: %s\n\n", data)
			fl.Flush()
		case <-globeTick.C:
			points, err := s.st.Globe(time.Now().Add(-time.Hour))
			if err != nil {
				continue
			}
			data, _ := json.Marshal(points)
			fmt.Fprintf(w, "event: globe\ndata: %s\n\n", data)
			fl.Flush()
		}
	}
}

func defaultStr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// validatePolicyValue checks the list syntax a policy kind expects, so a typo
// cannot silently compile into a rule that never matches.
func validatePolicyValue(kind, value string) string {
	switch kind {
	case model.PolicyIPWhitelist, model.PolicyIPBlacklist:
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if _, err := netip.ParsePrefix(part); err != nil {
				if _, err := netip.ParseAddr(part); err != nil {
					return "invalid IP or CIDR: " + part
				}
			}
		}
	case model.PolicyCountryWhitelist, model.PolicyCountryBlacklist:
		for _, part := range strings.Split(value, ",") {
			p := strings.ToUpper(strings.TrimSpace(part))
			if p == "" {
				continue
			}
			if len(p) != 2 || p[0] < 'A' || p[0] > 'Z' || p[1] < 'A' || p[1] > 'Z' {
				return "invalid ISO country code: " + p
			}
		}
	case model.PolicyASNBlock:
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if n, err := strconv.Atoi(part); err != nil || n < 1 {
				return "invalid ASN: " + part
			}
		}
	case "rate_limit":
		parts := strings.Split(value, "/")
		if len(parts) != 2 {
			return "rate_limit value must be rps/burst"
		}
		for _, p := range parts {
			if n, err := strconv.Atoi(strings.TrimSpace(p)); err != nil || n < 1 {
				return "rate_limit values must be positive integers"
			}
		}
	}
	return ""
}

// validFeedURL accepts public http(s) lists only: a threat feed has no reason
// to live on loopback or inside the LAN, so those targets are refused.
func validFeedURL(raw string) bool {
	return urlguard.Check(raw, urlguard.Feed) == nil
}
