package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/backup"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
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
func (s *Server) backupDocument() ([]byte, error) { return BuildBackupDocument(s.st) }

// BuildBackupDocument renders the export the console, the scheduler and the
// backup command all write, so every file restores the same way.
func BuildBackupDocument(st *store.Store) ([]byte, error) {
	kv, _ := st.Settings()
	safe := map[string]string{}
	for _, k := range publicSettingKeys {
		safe[k] = kv[k]
	}
	list, _ := st.ListProxies()
	proxies := make([]backupProxy, 0, len(list))
	for _, p := range list {
		bp := backupProxy{Proxy: p}
		bp.Upstreams, _ = st.ListUpstreams(p.ID)
		bp.Routes, _ = st.ListRoutes(p.ID)
		proxies = append(proxies, bp)
	}
	bans, _ := st.ListBans(true)
	policies, _ := st.ListPolicies()
	feeds, _ := st.ListFeeds()

	backup := backupFile{
		Version: "1.0", ExportedAt: time.Now().UTC(), Settings: safe,
		Proxies: proxies, Policies: policies, Feeds: feeds, Bans: bans,
		Note: "Secrets, gate passwords, private keys and administrator hashes are excluded. " +
			"Gate modes are reset to off on restore; re-issue certificates and reset passwords afterwards.",
	}
	return json.Marshal(backup)
}

// sealDownload encrypts a downloaded file when the request names a passphrase,
// so the same passphrase covers the manual download and the scheduled file.
func sealDownload(r *http.Request, data []byte) ([]byte, bool, error) {
	pass := r.Header.Get("X-Backup-Passphrase")
	if pass == "" {
		return data, false, nil
	}
	if len(pass) < 16 {
		return nil, false, errors.New("the passphrase must be at least 16 characters")
	}
	sealed, err := backup.Encrypt(pass, data)
	return sealed, true, err
}

func (s *Server) exportBackup(w http.ResponseWriter, r *http.Request) {
	data, err := s.backupDocument()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot build the backup")
		return
	}
	data, sealed, err := sealDownload(r, data)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	name, kind := "wafproxy-backup.json", "application/json"
	if sealed {
		name, kind = name+".enc", "application/octet-stream"
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Type", kind)
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
	if backup.IsEncrypted(body) {
		plain, err := backup.Decrypt(r.Header.Get("X-Backup-Passphrase"), body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		body = plain
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

	result["settings"], problems = s.applySettings(r, in.Settings, problems)
	result["proxies"], problems = s.applyProxies(r, in.Proxies, problems)
	result["policies"], problems = s.applyPolicies(r, in.Policies, problems)

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
		if _, err := s.db(r).CreateFeed(&f); err != nil {
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
	s.db(r).AddAudit(sess.Username, action, fmt.Sprint(result), clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"imported": result, "problems": problems})
}

// applySettings imports the settings every configuration document carries.
func (s *Server) applySettings(r *http.Request, in map[string]string, problems []string) (int, []string) {
	allowed := map[string]bool{}
	for _, k := range publicSettingKeys {
		allowed[k] = true
	}
	next := map[string]string{}
	for k, v := range in {
		if !allowed[k] {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" {
			continue // an empty exported value means "use the default"
		}
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
			clean, msg := s.cleanDecoyHosts(r, v)
			if msg != "" {
				problems = append(problems, "settings: "+msg+" skipped")
				continue
			}
			v = clean
		}
		next[k] = v
	}
	if len(next) > 0 {
		if err := s.db(r).SetSettings(next); err != nil {
			problems = append(problems, "settings: "+err.Error())
		}
	}
	return len(next), problems
}

// applyProxies adds the hosts that do not exist yet.
func (s *Server) applyProxies(r *http.Request, in []backupProxy, problems []string) (int, []string) {
	added := 0
	for _, bp := range in {
		host := strings.ToLower(strings.TrimSpace(bp.Hostname))
		if !validHostname(host) {
			problems = append(problems, "proxy "+host+": invalid hostname")
			continue
		}
		if _, err := s.db(r).ProxyByHost(host); err == nil {
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
		id, err := s.db(r).CreateProxy(&p)
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
			ups = append(ups, model.Upstream{URL: strings.TrimSpace(u.URL), Weight: u.Weight, Enabled: u.Enabled, MaxConns: u.MaxConns})
		}
		if err := s.db(r).ReplaceUpstreams(id, ups); err != nil {
			problems = append(problems, "proxy "+host+" upstreams: "+err.Error())
		}
		if err := s.db(r).ReplaceRoutes(id, bp.Routes); err != nil {
			problems = append(problems, "proxy "+host+" routes: "+err.Error())
		}
		added++
	}
	return added, problems
}

// applyPolicies adds every valid policy; policies have no name to match on.
func (s *Server) applyPolicies(r *http.Request, in []model.Policy, problems []string) (int, []string) {
	validPolicyKind := map[string]bool{
		model.PolicyIPWhitelist: true, model.PolicyCountryWhitelist: true, model.PolicyCountryBlacklist: true,
		model.PolicyASNBlock: true, model.PolicyDecoy: true, "rate_limit": true,
	}
	added := 0
	for i := range in {
		p := in[i]
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
		if _, err := s.db(r).CreatePolicy(&p); err != nil {
			problems = append(problems, "policy "+p.Value+": "+err.Error())
			continue
		}
		added++
	}
	return added, problems
}
