package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/urlguard"
)

// backupProxy is one proxy with its children, as stored in an export file.
type backupProxy struct {
	model.Proxy
	Upstreams []model.Upstream `json:"upstreams"`
	Routes    []model.Route    `json:"routes"`
}

// backupFile is the on-disk backup format. Unknown fields are rejected so a
// malformed or future file cannot silently change behaviour.
type backupFile struct {
	Version    string            `json:"version"`
	ExportedAt time.Time         `json:"exported_at"`
	Note       string            `json:"note"`
	Settings   map[string]string `json:"settings"`
	Proxies    []backupProxy     `json:"proxies"`
	Policies   []model.Policy    `json:"policies"`
	Feeds      []model.Feed      `json:"feeds"`
	Bans       []model.Ban       `json:"bans"`
}

// backupDocument renders the same configuration export the download serves and
// the scheduler writes, so a scheduled file restores exactly like a manual one.
func (s *Server) backupDocument() ([]byte, error) {
	kv, _ := s.st.Settings()
	safe := map[string]string{}
	for _, k := range publicSettingKeys {
		safe[k] = kv[k]
	}
	list, _ := s.st.ListProxies()
	proxies := make([]backupProxy, 0, len(list))
	for _, p := range list {
		bp := backupProxy{Proxy: p}
		bp.Upstreams, _ = s.st.ListUpstreams(p.ID)
		bp.Routes, _ = s.st.ListRoutes(p.ID)
		proxies = append(proxies, bp)
	}
	bans, _ := s.st.ListBans(true)
	policies, _ := s.st.ListPolicies()
	feeds, _ := s.st.ListFeeds()

	backup := backupFile{
		Version: "1.0", ExportedAt: time.Now().UTC(), Settings: safe,
		Proxies: proxies, Policies: policies, Feeds: feeds, Bans: bans,
		Note: "Secrets, gate passwords, private keys and administrator hashes are excluded. " +
			"Gate modes are reset to off on restore; re-issue certificates and reset passwords afterwards.",
	}
	return json.Marshal(backup)
}

func (s *Server) exportBackup(w http.ResponseWriter, r *http.Request) {
	data, err := s.backupDocument()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot build the backup")
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=wafproxy-backup.json")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

// restoreBackup imports settings, proxies, policies, feeds and bans. It is
// additive: existing hostnames are skipped rather than overwritten.
func (s *Server) restoreBackup(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid backup file")
		return
	}
	s.applyBackup(w, r, body, "backup.restore")
}

// applyBackup runs the import after the document has been decoded as JSON. The
// YAML import converts to JSON and lands here so both formats share every rule.
func (s *Server) applyBackup(w http.ResponseWriter, r *http.Request, body []byte, action string) {
	var in backupFile
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid backup file")
		return
	}
	if in.Version == "" {
		writeError(w, http.StatusBadRequest, "backup has no version")
		return
	}

	result := map[string]int{"settings": 0, "proxies": 0, "policies": 0, "feeds": 0, "bans": 0}
	var problems []string

	if len(in.Settings) > 0 {
		allowed := map[string]bool{}
		for _, k := range publicSettingKeys {
			allowed[k] = true
		}
		next := map[string]string{}
		for k, v := range in.Settings {
			if !allowed[k] {
				continue
			}
			v = strings.TrimSpace(v)
			switch k {
			case "wan_ip", "lan_ip":
				if net.ParseIP(v) == nil {
					problems = append(problems, "settings: invalid "+k+" skipped")
					continue
				}
			case "wan_port", "gui_port":
				n, err := strconv.Atoi(v)
				if err != nil || n < 1 || n > 65535 {
					problems = append(problems, "settings: invalid "+k+" skipped")
					continue
				}
			case "decoy_hosts":
				clean, msg := s.cleanDecoyHosts(v)
				if msg != "" {
					problems = append(problems, "settings: "+msg+" skipped")
					continue
				}
				v = clean
			}
			next[k] = v
			result["settings"]++
		}
		if err := s.st.SetSettings(next); err != nil {
			problems = append(problems, "settings: "+err.Error())
		}
	}

	for _, bp := range in.Proxies {
		host := strings.ToLower(strings.TrimSpace(bp.Hostname))
		if !validHostname(host) {
			problems = append(problems, "proxy "+host+": invalid hostname")
			continue
		}
		if _, err := s.st.ProxyByHost(host); err == nil {
			problems = append(problems, "proxy "+host+": already exists, skipped")
			continue
		}
		p := bp.Proxy
		p.ID = 0
		p.Hostname = host
		// Gate secrets are never exported, so enabling a gate during restore
		// would lock the proxy with no working credential.
		p.GateMode = "off"
		p.GateSecret = ""
		p.AuthProviderID = nil
		p.GateTOTPHint = ""
		if p.Fingerprint == "" {
			p.Fingerprint = "strict"
		}
		if p.WAFMode == "" {
			p.WAFMode = "inherit"
		}
		id, err := s.st.CreateProxy(&p)
		if err != nil {
			problems = append(problems, "proxy "+host+": "+err.Error())
			continue
		}
		var ups []model.Upstream
		for _, u := range bp.Upstreams {
			if err := urlguard.Check(u.URL, urlguard.Upstream); err != nil {
				problems = append(problems, "proxy "+host+": bad upstream "+u.URL+": "+err.Error())
				continue
			}
			ups = append(ups, model.Upstream{URL: strings.TrimSpace(u.URL), Weight: u.Weight, Enabled: u.Enabled})
		}
		if err := s.st.ReplaceUpstreams(id, ups); err != nil {
			problems = append(problems, "proxy "+host+" upstreams: "+err.Error())
		}
		if err := s.st.ReplaceRoutes(id, bp.Routes); err != nil {
			problems = append(problems, "proxy "+host+" routes: "+err.Error())
		}
		result["proxies"]++
	}

	validPolicyKind := map[string]bool{
		model.PolicyIPWhitelist: true, model.PolicyCountryWhitelist: true, model.PolicyCountryBlacklist: true,
		model.PolicyASNBlock: true, model.PolicyDecoy: true, "rate_limit": true,
	}
	for i := range in.Policies {
		p := in.Policies[i]
		if !validPolicyKind[p.Kind] {
			problems = append(problems, "policy: unknown kind "+p.Kind)
			continue
		}
		switch p.Action {
		case "allow", "block", "challenge", "log":
		default:
			p.Action = "block"
		}
		if strings.TrimSpace(p.Value) == "" {
			problems = append(problems, "policy: empty value skipped")
			continue
		}
		p.ID = 0
		if _, err := s.st.CreatePolicy(&p); err != nil {
			problems = append(problems, "policy "+p.Value+": "+err.Error())
			continue
		}
		result["policies"]++
	}

	for i := range in.Feeds {
		f := in.Feeds[i]
		if f.Local {
			problems = append(problems, "feed "+f.Name+": local uploads are not included in backups; upload the file again")
			continue
		}
		parsed, err := url.Parse(strings.TrimSpace(f.URL))
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			problems = append(problems, "feed "+f.Name+": bad url")
			continue
		}
		f.ID = 0
		f.Builtin = false
		f.State = "pending"
		if f.Action != "block" && f.Action != "challenge" && f.Action != "log" {
			f.Action = "block"
		}
		if _, err := s.st.CreateFeed(&f); err != nil {
			problems = append(problems, "feed "+f.Name+": "+err.Error())
			continue
		}
		result["feeds"]++
	}

	for _, b := range in.Bans {
		if strings.TrimSpace(b.CIDR) == "" {
			continue
		}
		ttl := time.Duration(0)
		if !b.Permanent {
			// A temporary ban without an expiry would otherwise restore as a
			// permanent ban (ttl 0). Skip it rather than locking someone out.
			if b.ExpiresAt == nil {
				problems = append(problems, "ban "+b.CIDR+": missing expiry, skipped")
				continue
			}
			d := time.Until(*b.ExpiresAt)
			if d <= 0 {
				continue
			}
			ttl = d
		}
		source := b.Source
		if source == "" {
			source = "restore"
		}
		reason := b.Reason
		if reason == "" {
			reason = "restored from backup"
		}
		if _, err := s.bans.Add(b.CIDR, reason, source, "restore", ttl); err != nil {
			problems = append(problems, "ban "+b.CIDR+": "+err.Error())
			continue
		}
		result["bans"]++
	}

	_ = s.policy.Reload()
	if err := s.proxy.Reload(r.Context()); err != nil {
		problems = append(problems, "reload: "+err.Error())
	}
	if iface := in.Settings["wan_iface"]; iface != "" {
		s.metrics.SetInterfaces(iface, in.Settings["lan_iface"])
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, action, fmt.Sprint(result), clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"imported": result, "problems": problems})
}
