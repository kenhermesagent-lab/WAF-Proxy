package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/acme"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// ---------- proxies ----------

type upstreamBody struct {
	// ID and ProxyID are accepted because the GUI round-trips the objects it
	// reads back; they are ignored on write.
	ID      int64  `json:"id"`
	ProxyID int64  `json:"proxy_id"`
	URL     string `json:"url"`
	Weight  int    `json:"weight"`
	Enabled bool   `json:"enabled"`
}

type proxyBody struct {
	// ID is accepted but the path parameter is authoritative.
	ID          int64          `json:"id"`
	Hostname    string         `json:"hostname"`
	Enabled     *bool          `json:"enabled"`
	ProfileID   *int64         `json:"profile_id"`
	CertID      *int64         `json:"cert_id"`
	GateMode    string         `json:"gate_mode"`
	GateSecret  string         `json:"gate_secret"`
	Fingerprint string         `json:"fingerprint"`
	BotLevel    string         `json:"bot_level"`
	Maintenance *bool          `json:"maintenance"`
	WAFMode     string         `json:"waf_mode"`
	Upstreams   []upstreamBody `json:"upstreams"`
	Routes      []model.Route  `json:"routes"`
	GateUsers   []string       `json:"gate_users"`
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

func (s *Server) getProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	p, err := s.st.GetProxy(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	v := proxyView{Proxy: *p}
	v.Upstreams, _ = s.st.ListUpstreams(id)
	v.Routes, _ = s.st.ListRoutes(id)
	v.GateUsers, _ = s.st.GateACL(id)
	writeJSON(w, http.StatusOK, v)
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
		GateMode:    defaultStr(in.GateMode, "off"),
		Fingerprint: defaultStr(in.Fingerprint, "strict"),
		BotLevel:    defaultStr(in.BotLevel, "light"),
		WAFMode:     defaultStr(in.WAFMode, "inherit"),
	}
	if in.Maintenance != nil {
		p.Maintenance = *in.Maintenance
	}
	if msg := validateProxyOptions(in); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if msg := validateUpstreams(in.Upstreams); msg != "" {
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
	id, err := s.st.CreateProxy(p)
	if err != nil {
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
	if msg := validateProxyOptions(in); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if msg := validateUpstreams(in.Upstreams); msg != "" {
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
	if err := s.st.UpdateProxy(current); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update")
		return
	}
	s.saveChildren(id, in)
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "proxy.update", current.Hostname, clientIP(r))
	writeJSON(w, http.StatusOK, current)
}

func validateProxyOptions(in proxyBody) string {
	modes := map[string]bool{"off": true, "passphrase": true, "accounts": true, "accounts_totp": true}
	if in.GateMode != "" && !modes[in.GateMode] {
		return "invalid gate mode"
	}
	if in.WAFMode != "" && in.WAFMode != "inherit" && in.WAFMode != "off" && in.WAFMode != "detect" && in.WAFMode != "block" {
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
		parsed, err := url.Parse(raw)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return "upstream must be an http(s) URL: " + raw
		}
		host := strings.ToLower(parsed.Hostname())
		if host == "169.254.169.254" || host == "metadata.google.internal" || host == "metadata.goog" {
			return "upstream may not point at a cloud metadata endpoint"
		}
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
		ups = append(ups, model.Upstream{ProxyID: proxyID, URL: u.URL, Weight: w, Enabled: u.Enabled})
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
	s.st.AddAudit(sess.Username, "proxy.delete", name, clientIP(r))
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
	return ""
}

type gateBody struct {
	Mode   string   `json:"mode"`
	Secret string   `json:"secret"`
	Users  []string `json:"users"`
}

func (s *Server) setGate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	p, err := s.st.GetProxy(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	var in gateBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if in.Mode != "" {
		p.GateMode = in.Mode
	}
	if in.Secret != "" {
		enc, err := s.box.Seal(in.Secret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encryption error")
			return
		}
		p.GateSecret = enc
	}
	if err := s.st.UpdateProxy(p); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update")
		return
	}
	if in.Users != nil {
		_ = s.st.SetGateACL(id, in.Users)
	}
	_ = s.st.DeleteProxyGateSessions(id)
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "proxy.gate", p.Hostname, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) revokeGate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	_ = s.st.DeleteProxyGateSessions(id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) reload(ctx context.Context) {
	if err := s.policy.Reload(); err != nil {
		s.log.Error("reload policies", "err", err)
	}
	if err := s.proxy.Reload(ctx); err != nil {
		s.log.Error("reload proxy routes", "err", err)
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
		p.Mode = in.Mode
	}
	if in.Paranoia >= 1 && in.Paranoia <= 4 {
		p.Paranoia = in.Paranoia
	}
	if in.Anomaly > 0 {
		p.Anomaly = in.Anomaly
	}
	if in.AllowedMethods != "" {
		p.AllowedMethods = in.AllowedMethods
	}
	if in.MaxBody > 0 {
		p.MaxBody = in.MaxBody
	}
	p.Exceptions = in.Exceptions
	if err := s.st.UpdateProfile(p); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update")
		return
	}
	if err := s.policy.ReloadWAF(); err != nil {
		s.log.Error("reload WAF profiles", "err", err)
	}
	writeJSON(w, http.StatusOK, p)
}

// ---------- policies ----------

var policyKinds = map[string]bool{
	model.PolicyIPWhitelist: true, model.PolicyCountryWhitelist: true,
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
	writeJSON(w, http.StatusCreated, in)
}

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in model.Policy
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	in.ID = id
	if !policyKinds[in.Kind] {
		writeError(w, http.StatusBadRequest, "unknown policy kind")
		return
	}
	if strings.TrimSpace(in.Value) == "" {
		writeError(w, http.StatusBadRequest, "value is required")
		return
	}
	if in.Scope == "" {
		in.Scope = "global"
	}
	if in.Scope == "proxy" && in.ProxyID == nil {
		writeError(w, http.StatusBadRequest, "proxy scope requires proxy_id")
		return
	}
	if msg := validatePolicyValue(in.Kind, in.Value); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if err := s.st.UpdatePolicy(&in); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update")
		return
	}
	s.reload(r.Context())
	writeJSON(w, http.StatusOK, in)
}

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.st.DeletePolicy(id); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot delete")
		return
	}
	s.reload(r.Context())
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------- bans ----------

func (s *Server) listBans(w http.ResponseWriter, r *http.Request) {
	all := r.URL.Query().Get("all") == "1"
	list, err := s.bans.List(all)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	active, reason := s.bans.KernelStatus()
	writeJSON(w, http.StatusOK, map[string]any{
		"bans": list, "active": s.bans.Count(),
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
		if in.TTL <= 0 {
			in.TTL = 86400
		}
		if in.TTL > 31536000 {
			writeError(w, http.StatusBadRequest, "ttl too large")
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
	writeJSON(w, http.StatusCreated, rec)
}

func (s *Server) deleteBan(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	list, err := s.bans.List(true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	for _, b := range list {
		if b.ID == id {
			if err := s.bans.Remove(b.CIDR); err != nil {
				writeError(w, http.StatusInternalServerError, "cannot remove ban")
				return
			}
			return
		}
	}
	writeError(w, http.StatusNotFound, "not found")
}

func (s *Server) promoteBan(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	list, err := s.bans.List(true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	for _, b := range list {
		if b.ID == id {
			if err := s.bans.Promote(b.CIDR); err != nil {
				writeError(w, http.StatusInternalServerError, "cannot promote")
				return
			}
			sess := sessionFrom(r)
			s.st.AddAudit(sess.Username, "ban.promote", b.CIDR, clientIP(r))
			return
		}
	}
	writeError(w, http.StatusNotFound, "not found")
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
	in.Enabled = true
	id, err := s.st.CreateFeed(&in)
	if err != nil {
		writeError(w, http.StatusConflict, "feed already exists")
		return
	}
	go s.feeds.Refresh(context.Background(), id)
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
	if !validFeedURL(in.URL) {
		writeError(w, http.StatusBadRequest, "feed url must be http(s)")
		return
	}
	if in.IntervalS <= 0 {
		in.IntervalS = 900
	}
	if err := s.st.UpdateFeed(&in); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update")
		return
	}
	go s.feeds.Refresh(context.Background(), id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) deleteFeed(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.st.DeleteFeed(id); err != nil {
		writeError(w, http.StatusBadRequest, "builtin feeds cannot be deleted")
		return
	}
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

func (s *Server) intelStatus(w http.ResponseWriter, r *http.Request) {
	active, reason := s.bans.KernelStatus()
	writeJSON(w, http.StatusOK, map[string]any{
		"feeds": s.feeds.Status(), "total": s.feeds.Total(),
		"kernel": map[string]any{"active": active, "reason": reason},
		"geoip":  s.geo.Available(),
	})
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
	creds, _ := s.st.ListDNSCredentials()
	writeJSON(w, http.StatusOK, map[string]any{"certs": out, "credentials": creds, "providers": acme.Providers})
}

type certBody struct {
	Domains  string            `json:"domains"`
	Provider string            `json:"provider"`
	Creds    map[string]string `json:"creds"`
}

func (s *Server) createCert(w http.ResponseWriter, r *http.Request) {
	var in certBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	in.Domains = strings.TrimSpace(in.Domains)
	if in.Domains == "" || in.Provider == "" {
		writeError(w, http.StatusBadRequest, "domains and provider are required")
		return
	}
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
	for _, d := range strings.Split(in.Domains, ",") {
		d = strings.TrimSpace(d)
		if strings.HasPrefix(d, "*.") {
			d = d[2:]
		}
		if !validHostname(d) {
			writeError(w, http.StatusBadRequest, "invalid domain: "+d)
			return
		}
	}
	if len(in.Creds) > 0 {
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
		Wildcard: strings.Contains(in.Domains, "*."),
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
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "renewing"})
}

func (s *Server) deleteCert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.st.DeleteCert(id); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot delete")
		return
	}
	_ = s.certs.Load()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) dnsProviders(w http.ResponseWriter, r *http.Request) {
	creds, _ := s.st.ListDNSCredentials()
	writeJSON(w, http.StatusOK, map[string]any{"providers": acme.Providers, "credentials": creds})
}

func (s *Server) listDNSCredentials(w http.ResponseWriter, r *http.Request) {
	creds, err := s.st.ListDNSCredentials()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, creds)
}

// ---------- observability ----------

func (s *Server) getMetrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.metrics.Snapshot())
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.EventFilter{Limit: 100}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Offset = n
		}
	}
	if v := q.Get("ip"); v != "" {
		f.SrcIP = v
	}
	if v := q.Get("country"); v != "" {
		f.Country = v
	}
	if v := q.Get("stage"); v != "" {
		f.Stage = v
	}
	if v := q.Get("action"); v != "" {
		f.Action = v
	}
	if v := q.Get("host"); v != "" {
		f.Host = v
	}
	if v := q.Get("proxy_id"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			f.ProxyID = &n
		}
	}
	f.BlockedOnly = q.Get("blocked") == "1"
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.From = t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.To = t
		}
	}
	events, total, err := s.st.QueryEvents(f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "total": total})
}

func (s *Server) getGlobe(w http.ResponseWriter, r *http.Request) {
	points, err := s.st.Globe(time.Now().Add(-15 * time.Minute))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, points)
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListAudit(200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// ---------- notifications ----------

func (s *Server) getNotifications(w http.ResponseWriter, r *http.Request) {
	settings, err := s.notify.Settings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	recent, _ := s.st.RecentAlerts(50)
	writeJSON(w, http.StatusOK, map[string]any{
		"settings": settings, "channels": s.notify.Channels(), "recent": recent,
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
	if err := s.notify.Test(in.Channel); err != nil {
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
	if in.TOTPEnabled {
		secret, err = auth.NewTOTPSecret()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "cannot generate secret")
			return
		}
	}
	enc, err := s.box.Seal(secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encryption error")
		return
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
	if in.TOTPEnabled != nil {
		enabled = *in.TOTPEnabled
		if enabled && secret == "" {
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
		}
	}
	if err := s.st.UpdateGateUser(id, hash, secret, enabled); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) deleteGateUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.st.DeleteGateUser(id); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot delete")
		return
	}
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
			data, err := json.Marshal(s.metrics.Snapshot())
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: metrics\ndata: %s\n\n", data)
			fl.Flush()
		case <-globeTick.C:
			points, err := s.st.Globe(time.Now().Add(-15 * time.Minute))
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
	case model.PolicyIPWhitelist:
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

func validFeedURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}
