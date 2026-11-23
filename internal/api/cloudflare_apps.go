package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	cf "github.com/kenhermesagent-lab/waf-proxy-docker/internal/cloudflared"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// cloudflareApp is one site hostname as the Apps tab shows it. In token mode the
// ingress rules live in the Cloudflare dashboard, so the console hands the
// operator the exact values instead of pretending it wrote them.
type cloudflareApp struct {
	Hostname    string `json:"hostname"`
	Enabled     bool   `json:"enabled"`
	Published   bool   `json:"published"`
	HasCert     bool   `json:"has_cert"`
	Service     string `json:"service"`
	OriginName  string `json:"origin_server_name"`
	NoTLSVerify bool   `json:"no_tls_verify"`
}

type cloudflareAppsView struct {
	Site      string                       `json:"site"`
	TunnelID  string                       `json:"tunnel_id"`
	Connected bool                         `json:"connected"`
	WANPort   int                          `json:"wan_port"`
	Apps      []cloudflareApp              `json:"apps"`
	Checks    map[string][]cloudflareCheck `json:"checks"`
	Checked   map[string]string            `json:"checked"`
}

// cloudflareApps lists the site's hostnames with their publish state.
func (s *Server) cloudflareApps(r *http.Request) (cloudflareAppsView, error) {
	kv, err := s.db(r).Settings()
	if err != nil {
		return cloudflareAppsView{}, err
	}
	hostKV, err := s.st.Settings()
	if err != nil {
		return cloudflareAppsView{}, err
	}
	proxies, err := s.db(r).ListProxies()
	if err != nil {
		return cloudflareAppsView{}, err
	}
	wanPort := settingPort(hostKV["wan_port"], 443)
	published := cf.Published(kv)
	site := ""
	if rec, err := s.st.SiteByID(s.db(r).SiteID()); err == nil && rec != nil {
		site = rec.Slug
	}
	connector := cf.Load(hostKV, s.box)
	view := cloudflareAppsView{
		Site:      site,
		TunnelID:  connector.TunnelID,
		Connected: connector.Enabled && s.cloudflared != nil && s.cloudflared.Snapshot().State == cf.StateRunning,
		WANPort:   wanPort,
		Apps:      make([]cloudflareApp, 0, len(proxies)),
		Checks:    map[string][]cloudflareCheck{},
		Checked:   map[string]string{},
	}
	s.cfAppMu.Lock()
	for _, host := range published {
		key := appCheckKey(s.db(r).SiteID(), host)
		if v, ok := s.cfAppChecks[key]; ok {
			view.Checks[host] = v
		}
		if v, ok := s.cfAppChecked[key]; ok {
			view.Checked[host] = v
		}
	}
	s.cfAppMu.Unlock()
	for _, p := range proxies {
		view.Apps = append(view.Apps, cloudflareApp{
			Hostname:    p.Hostname,
			Enabled:     p.Enabled,
			Published:   containsHost(published, p.Hostname),
			HasCert:     p.CertID != nil,
			Service:     "https://127.0.0.1:" + strconv.Itoa(wanPort),
			OriginName:  p.Hostname,
			NoTLSVerify: true,
		})
	}
	return view, nil
}

func appCheckKey(site int64, host string) string {
	return strconv.FormatInt(site, 10) + "/" + host
}

func containsHost(list []string, host string) bool {
	for _, h := range list {
		if strings.EqualFold(h, host) {
			return true
		}
	}
	return false
}

func (s *Server) getCloudflareApps(w http.ResponseWriter, r *http.Request) {
	view, err := s.cloudflareApps(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// putCloudflareApps replaces the site's published hostname list. Only hostnames
// this site already proxies are accepted, so the page cannot publish a name it
// does not own.
func (s *Server) putCloudflareApps(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Published []string `json:"published"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	proxies, err := s.db(r).ListProxies()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	known := make(map[string]bool, len(proxies))
	for _, p := range proxies {
		known[store.NormalizeHost(p.Hostname)] = true
	}
	next := make([]string, 0, len(in.Published))
	for _, h := range in.Published {
		host := store.NormalizeHost(h)
		if host == "" || !known[host] {
			writeError(w, http.StatusBadRequest, "only hostnames configured on this site can be published: "+strings.TrimSpace(h))
			return
		}
		next = append(next, host)
	}
	if err := s.db(r).SetSettings(map[string]string{
		cf.KeyPublished: cf.EncodePublished(next),
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot save settings")
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "cloudflare.publish", "published "+strings.Join(next, ", "), clientIP(r))
	s.cfAppMu.Lock()
	for key := range s.cfAppChecks {
		delete(s.cfAppChecks, key)
	}
	for key := range s.cfAppChecked {
		delete(s.cfAppChecked, key)
	}
	s.cfAppMu.Unlock()
	view, err := s.cloudflareApps(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) checkCloudflareApps(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Hostnames []string `json:"hostnames"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	kv, err := s.db(r).Settings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	published := cf.Published(kv)
	if len(in.Hostnames) == 0 {
		in.Hostnames = published
	}
	if len(in.Hostnames) == 0 {
		writeError(w, http.StatusBadRequest, "publish a hostname before checking")
		return
	}
	for _, h := range in.Hostnames {
		if !containsHost(published, store.NormalizeHost(h)) {
			writeError(w, http.StatusBadRequest, "only published hostnames for this site can be checked")
			return
		}
	}
	results := map[string][]cloudflareCheck{}
	checked := map[string]string{}
	now := time.Now().Format(time.RFC3339)
	for _, raw := range in.Hostnames {
		host := store.NormalizeHost(raw)
		results[host] = s.runAppChecks(r.Context(), host)
		checked[host] = now
	}
	s.cfAppMu.Lock()
	if s.cfAppChecks == nil {
		s.cfAppChecks = map[string][]cloudflareCheck{}
	}
	if s.cfAppChecked == nil {
		s.cfAppChecked = map[string]string{}
	}
	site := s.db(r).SiteID()
	for host, checks := range results {
		s.cfAppChecks[appCheckKey(site, host)] = checks
		s.cfAppChecked[appCheckKey(site, host)] = checked[host]
	}
	s.cfAppMu.Unlock()
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "cloudflare.check_apps", "checked "+strings.Join(in.Hostnames, ", "), clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"checks": results, "checked": checked})
}

// runAppChecks verifies that a published hostname reaches Cloudflare and that
// Access answers before the app does. There is no origin marker for an app, so
// the row does not claim one.
func (s *Server) runAppChecks(ctx context.Context, host string) []cloudflareCheck {
	dnsCheck, directCheck := hostDnsChecks(ctx, host)
	probe := s.probeEdge(ctx, host, "/")
	edgeOK := probe.cfRay != ""
	edgeDetail := "a Cloudflare edge answered for the hostname"
	if probe.err != nil {
		edgeDetail = probe.err.Error()
	} else if !edgeOK {
		edgeDetail = "the response carries no CF-Ray: it did not come from Cloudflare"
	}
	accessOn := probe.status == http.StatusFound && strings.Contains(probe.location, "cloudflareaccess.com")
	accessDetail := "Access prompts before the app loads"
	if !accessOn {
		if probe.err != nil {
			accessDetail = "cannot tell: " + probe.err.Error()
		} else {
			accessDetail = "no sign-in prompt: the app is reachable without Access"
		}
	}
	return []cloudflareCheck{
		dnsCheck,
		directCheck,
		{ID: "edge", Label: "Request reaches the edge", OK: edgeOK, Detail: edgeDetail},
		{ID: "access", Label: "Cloudflare Access protects the app", OK: accessOn, Detail: accessDetail},
	}
}

// hostDnsChecks resolves a hostname and separates "points at Cloudflare" from
// "also answers from this host", which is the one that bypasses Access.
func hostDnsChecks(ctx context.Context, host string) (cloudflareCheck, cloudflareCheck) {
	ips, err := lookupHost(ctx, host)
	proxied := 0
	exposed := false
	for _, ip := range ips {
		if isCloudflareIP(ip) {
			proxied++
		} else {
			exposed = true
		}
	}
	dns := cloudflareCheck{ID: "dns", Label: "Hostname points at Cloudflare"}
	switch {
	case err != nil:
		dns.Detail = "DNS lookup failed: " + err.Error()
	case len(ips) == 0:
		dns.Detail = "no address found for " + host
	case proxied == len(ips):
		dns.OK = true
		dns.Detail = "all addresses are Cloudflare"
	default:
		dns.Detail = "some addresses are not Cloudflare: the origin may still answer directly"
	}
	direct := cloudflareCheck{ID: "direct", Label: "No direct origin record"}
	switch {
	case err != nil || len(ips) == 0:
		direct.Detail = "cannot tell without a DNS answer"
	case exposed:
		direct.Detail = "a non-Cloudflare address answers for this hostname; a port forward would bypass Access"
	default:
		direct.OK = true
		direct.Detail = "only Cloudflare addresses answer for the hostname"
	}
	return dns, direct
}
