package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/backup"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// configDoc is the declarative half of a backup. Bans and feeds are live state,
// so they stay in the JSON backup and out of the YAML configuration. Every
// reference between rows is a name, so the file means the same thing on another
// install.
type configDoc struct {
	Version            string                    `json:"version"`
	ExportedAt         time.Time                 `json:"exported_at"`
	Note               string                    `json:"note"`
	Settings           map[string]string         `json:"settings"`
	WAFProfiles        []model.Profile           `json:"waf_profiles"`
	ProtectionProfiles []model.ProtectionProfile `json:"protection_profiles"`
	AccessLists        []configAccessList        `json:"access_lists"`
	AccessProfiles     []configAccessProfile     `json:"access_profiles"`
	Proxies            []configProxy             `json:"proxies"`
	Policies           []configPolicy            `json:"policies"`
}

type configAccessList struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	IPs       string `json:"ips"`
	Countries string `json:"countries"`
}

// configPolicy names the proxy it applies to instead of carrying its id.
type configPolicy struct {
	Scope    string `json:"scope"`
	Proxy    string `json:"proxy,omitempty"`
	Kind     string `json:"kind"`
	Value    string `json:"value"`
	Action   string `json:"action"`
	Priority int    `json:"priority"`
	Enabled  bool   `json:"enabled"`
	Note     string `json:"note"`
}

type configProxy struct {
	Hostname          string           `json:"hostname"`
	Enabled           bool             `json:"enabled"`
	WAFProfile        string           `json:"waf_profile,omitempty"`
	ProtectionProfile string           `json:"protection_profile,omitempty"`
	AccessProfile     string           `json:"access_profile,omitempty"`
	GateMode          string           `json:"gate_mode"`
	Fingerprint       string           `json:"fingerprint"`
	BotLevel          string           `json:"bot_level"`
	Maintenance       bool             `json:"maintenance"`
	WAFMode           string           `json:"waf_mode"`
	LBPolicy          string           `json:"lb_policy,omitempty"`
	HealthPath        string           `json:"health_path,omitempty"`
	HealthExpect      string           `json:"health_expect,omitempty"`
	HealthInterval    int              `json:"health_interval,omitempty"`
	HealthFailAfter   int              `json:"health_fail_after,omitempty"`
	MaxInflight       int              `json:"max_inflight,omitempty"`
	MaxInflightClient int              `json:"max_inflight_per_client,omitempty"`
	Upstreams         []configUpstream `json:"upstreams"`
	Routes            []configRoute    `json:"routes"`
}

type configUpstream struct {
	URL      string `json:"url"`
	Weight   int    `json:"weight"`
	Enabled  bool   `json:"enabled"`
	MaxConns int    `json:"max_conns,omitempty"`
}

type configRoute struct {
	Kind        string `json:"kind"`
	Match       string `json:"match"`
	Target      string `json:"target"`
	StripPrefix bool   `json:"strip_prefix"`
}

// configAccessProfile names its lists and policies, because numeric ids from
// another install mean nothing here.
type configAccessProfile struct {
	Name              string             `json:"name"`
	Rules             []configAccessRule `json:"rules"`
	Lists             []string           `json:"lists"`
	WAFProfile        string             `json:"waf_profile,omitempty"`
	ProtectionProfile string             `json:"protection_profile,omitempty"`
}

type configAccessRule struct {
	Policy string `json:"policy"` // "kind value", matching the policies list
	Role   string `json:"role"`
}

func (s *Server) configDocument() (configDoc, error) {
	kv, _ := s.st.Settings()
	safe := map[string]string{}
	for _, k := range publicSettingKeys {
		safe[k] = kv[k]
	}
	allProxies, err := s.st.ListProxies()
	if err != nil {
		return configDoc{}, err
	}
	wafAll, _ := s.st.ListProfiles()
	protectionAll, _ := s.st.ListProtectionProfiles()
	lists, _ := s.st.ListAccessLists()
	access, _ := s.st.ListAccessProfiles()
	policies, _ := s.st.ListPolicies()

	wafName := map[int64]string{}
	// Builtins are seeded on every install, so only operator profiles travel.
	waf := make([]model.Profile, 0, len(wafAll))
	for _, p := range wafAll {
		wafName[p.ID] = p.Name
		if !p.Builtin {
			waf = append(waf, p)
		}
	}
	protectionName := map[int64]string{}
	protection := make([]model.ProtectionProfile, 0, len(protectionAll))
	for _, p := range protectionAll {
		protectionName[p.ID] = p.Name
		if !p.Builtin {
			protection = append(protection, p)
		}
	}
	accessName := map[int64]string{}
	for _, a := range access {
		accessName[a.ID] = a.Name
	}
	listName := map[int64]string{}
	for _, l := range lists {
		listName[l.ID] = l.Name
	}
	policyRef := map[int64]string{}
	for _, p := range policies {
		policyRef[p.ID] = strings.TrimSpace(p.Kind + " " + p.Value)
	}
	hostName := map[int64]string{}
	for _, p := range allProxies {
		hostName[p.ID] = p.Hostname
	}

	profiles := make([]configAccessProfile, 0, len(access))
	for _, a := range access {
		row := configAccessProfile{Name: a.Name}
		if a.WAFProfileID != nil {
			row.WAFProfile = wafName[*a.WAFProfileID]
		}
		if a.ProtectionProfileID != nil {
			row.ProtectionProfile = protectionName[*a.ProtectionProfileID]
		}
		for _, id := range a.ListIDs {
			if name := listName[id]; name != "" {
				row.Lists = append(row.Lists, name)
			}
		}
		for _, rule := range a.Rules {
			row.Rules = append(row.Rules, configAccessRule{Policy: policyRef[rule.PolicyID], Role: rule.Role})
		}
		profiles = append(profiles, row)
	}

	hosts := make([]configProxy, 0, len(allProxies))
	for _, p := range allProxies {
		row := configProxy{
			Hostname: p.Hostname, Enabled: p.Enabled, GateMode: p.GateMode,
			Fingerprint: p.Fingerprint, BotLevel: p.BotLevel, Maintenance: p.Maintenance, WAFMode: p.WAFMode,
			LBPolicy: p.LBPolicy, HealthPath: p.HealthPath, HealthExpect: p.HealthExpect,
			HealthInterval: p.HealthInterval, HealthFailAfter: p.HealthFailAfter,
			MaxInflight: p.MaxInflight, MaxInflightClient: p.MaxInflightPerClient,
		}
		if p.ProfileID != nil {
			row.WAFProfile = wafName[*p.ProfileID]
		}
		if p.ProtectionProfileID != nil {
			row.ProtectionProfile = protectionName[*p.ProtectionProfileID]
		}
		if p.AccessProfileID != nil {
			row.AccessProfile = accessName[*p.AccessProfileID]
		}
		ups, _ := s.st.ListUpstreams(p.ID)
		for _, u := range ups {
			row.Upstreams = append(row.Upstreams, configUpstream{URL: u.URL, Weight: u.Weight, Enabled: u.Enabled, MaxConns: u.MaxConns})
		}
		routes, _ := s.st.ListRoutes(p.ID)
		for _, r := range routes {
			row.Routes = append(row.Routes, configRoute{Kind: r.Kind, Match: r.Match, Target: r.Target, StripPrefix: r.StripPrefix})
		}
		hosts = append(hosts, row)
	}

	exportedPolicies := make([]configPolicy, 0, len(policies))
	for _, p := range policies {
		row := configPolicy{
			Scope: p.Scope, Kind: p.Kind, Value: p.Value, Action: p.Action,
			Priority: p.Priority, Enabled: p.Enabled, Note: p.Note,
		}
		if p.ProxyID != nil {
			row.Proxy = hostName[*p.ProxyID]
		}
		exportedPolicies = append(exportedPolicies, row)
	}

	exportedLists := make([]configAccessList, 0, len(lists))
	for _, l := range lists {
		exportedLists = append(exportedLists, configAccessList{Kind: l.Kind, Name: l.Name, IPs: l.IPs, Countries: l.Countries})
	}

	return configDoc{
		Version: "1.0", ExportedAt: time.Now().UTC(), Settings: safe,
		WAFProfiles: waf, ProtectionProfiles: protection, AccessLists: exportedLists,
		AccessProfiles: profiles, Proxies: hosts, Policies: exportedPolicies,
		Note: "Declarative configuration only; bans, feeds, certificates and secrets are not included. " +
			"Every reference between rows is a name.",
	}, nil
}

// exportConfigYAML renders the declarative configuration as readable YAML.
func (s *Server) exportConfigYAML(w http.ResponseWriter, r *http.Request) {
	doc, err := s.configDocument()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot build the configuration")
		return
	}
	data, err := json.Marshal(doc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot convert the configuration")
		return
	}
	// Round-trip through JSON so the YAML keys are the same snake_case names.
	var generic any
	if err := json.Unmarshal(data, &generic); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot convert the configuration")
		return
	}
	out, err := yaml.Marshal(generic)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot convert the configuration")
		return
	}
	out, sealed, err := sealDownload(r, out)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	name, kind := "wafproxy.yaml", "application/yaml; charset=utf-8"
	if sealed {
		name, kind = name+".enc", "application/octet-stream"
	}
	w.Header().Set("Content-Type", kind)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write(out)
}

// importConfigYAML accepts the exported document and applies it additively,
// using the same settings, proxy and policy rules as a JSON backup.
func (s *Server) importConfigYAML(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid configuration file")
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
	var generic any
	if err := yaml.Unmarshal(body, &generic); err != nil {
		writeError(w, http.StatusBadRequest, "invalid configuration file")
		return
	}
	// Readable YAML invites unquoted numbers and booleans; the document stores
	// settings and the version as strings.
	if top, ok := generic.(map[string]any); ok {
		for _, key := range []string{"version", "note"} {
			if v, ok := top[key]; ok {
				top[key] = fmt.Sprint(v)
			}
		}
		if settings, ok := top["settings"].(map[string]any); ok {
			for key, v := range settings {
				settings[key] = fmt.Sprint(v)
			}
		}
	}
	data, err := json.Marshal(generic)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid configuration file")
		return
	}
	var in configDoc
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid configuration file")
		return
	}
	if in.Version == "" {
		writeError(w, http.StatusBadRequest, "configuration has no version")
		return
	}

	result := map[string]int{
		"settings": 0, "waf_profiles": 0, "protection_profiles": 0,
		"access_lists": 0, "access_profiles": 0, "proxies": 0, "policies": 0,
	}
	var problems []string

	result["settings"], problems = s.applySettings(in.Settings, problems)
	result["waf_profiles"], problems = s.applyWAFProfiles(in.WAFProfiles, problems)
	result["protection_profiles"], problems = s.applyProtectionProfiles(in.ProtectionProfiles, problems)
	result["access_lists"], problems = s.applyAccessLists(in.AccessLists, problems)
	// Proxies first: a proxy-scoped policy names its host. The access profile is
	// linked back afterwards, because it needs the policies created next.
	result["proxies"], problems = s.applyConfigProxies(in.Proxies, problems)
	result["policies"], problems = s.applyConfigPolicies(in.Policies, problems)
	result["access_profiles"], problems = s.applyAccessProfiles(in.AccessProfiles, problems)
	s.linkConfigProxyAccessProfiles(in.Proxies, problems)

	_ = s.policy.Reload()
	if err := s.proxy.Reload(r.Context()); err != nil {
		problems = append(problems, "reload: "+err.Error())
	}
	if iface := in.Settings["wan_iface"]; iface != "" {
		s.metrics.SetInterfaces(iface, in.Settings["lan_iface"])
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "config.import", fmt.Sprint(result), clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"imported": result, "problems": problems})
}

func (s *Server) applyWAFProfiles(in []model.Profile, problems []string) (int, []string) {
	existing := map[string]bool{}
	if list, err := s.st.ListProfiles(); err == nil {
		for _, p := range list {
			existing[p.Name] = true
		}
	}
	added := 0
	for _, p := range in {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			problems = append(problems, "waf profile: missing name")
			continue
		}
		if existing[name] {
			problems = append(problems, "waf profile "+name+": already exists, skipped")
			continue
		}
		p.ID, p.Name, p.Builtin = 0, name, false
		if err := s.st.CreateProfile(&p); err != nil {
			problems = append(problems, "waf profile "+name+": "+err.Error())
			continue
		}
		existing[name] = true
		added++
	}
	return added, problems
}

func (s *Server) applyProtectionProfiles(in []model.ProtectionProfile, problems []string) (int, []string) {
	existing := map[string]bool{}
	if list, err := s.st.ListProtectionProfiles(); err == nil {
		for _, p := range list {
			existing[p.Name] = true
		}
	}
	added := 0
	for _, p := range in {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			problems = append(problems, "protection profile: missing name")
			continue
		}
		if existing[name] {
			problems = append(problems, "protection profile "+name+": already exists, skipped")
			continue
		}
		p.ID, p.Name, p.Builtin = 0, name, false
		if err := s.st.CreateProtectionProfile(&p); err != nil {
			problems = append(problems, "protection profile "+name+": "+err.Error())
			continue
		}
		existing[name] = true
		added++
	}
	return added, problems
}

func (s *Server) applyAccessLists(in []configAccessList, problems []string) (int, []string) {
	existing := map[string]bool{}
	if list, err := s.st.ListAccessLists(); err == nil {
		for _, l := range list {
			existing[l.Name] = true
		}
	}
	added := 0
	for _, row := range in {
		name := strings.TrimSpace(row.Name)
		if name == "" {
			problems = append(problems, "access list: missing name")
			continue
		}
		if row.Kind != model.ListKindBlock && row.Kind != model.ListKindAllow {
			problems = append(problems, "access list "+name+": kind must be blocklist or whitelist")
			continue
		}
		if existing[name] {
			problems = append(problems, "access list "+name+": already exists, skipped")
			continue
		}
		list := model.AccessList{Kind: row.Kind, Name: name, IPs: row.IPs, Countries: row.Countries}
		if err := s.st.CreateAccessList(&list); err != nil {
			problems = append(problems, "access list "+name+": "+err.Error())
			continue
		}
		existing[name] = true
		added++
	}
	return added, problems
}

// applyConfigPolicies resolves the proxy hostname before handing the rows to the
// shared policy importer.
func (s *Server) applyConfigPolicies(in []configPolicy, problems []string) (int, []string) {
	proxyID := map[string]int64{}
	if list, err := s.st.ListProxies(); err == nil {
		for _, p := range list {
			proxyID[p.Hostname] = p.ID
		}
	}
	rows := make([]model.Policy, 0, len(in))
	for _, p := range in {
		row := model.Policy{
			Scope: p.Scope, Kind: p.Kind, Value: p.Value, Action: p.Action,
			Priority: p.Priority, Enabled: p.Enabled, Note: p.Note,
		}
		if p.Proxy != "" {
			id, ok := proxyID[p.Proxy]
			if !ok {
				problems = append(problems, "policy "+p.Kind+" "+p.Value+": unknown proxy "+p.Proxy+", skipped")
				continue
			}
			row.ProxyID = &id
		}
		rows = append(rows, row)
	}
	return s.applyPolicies(rows, problems)
}

// applyConfigProxies resolves profile names, then uses the shared proxy importer.
func (s *Server) applyConfigProxies(in []configProxy, problems []string) (int, []string) {
	wafID := map[string]int64{}
	if list, err := s.st.ListProfiles(); err == nil {
		for _, p := range list {
			wafID[p.Name] = p.ID
		}
	}
	protectionID := map[string]int64{}
	if list, err := s.st.ListProtectionProfiles(); err == nil {
		for _, p := range list {
			protectionID[p.Name] = p.ID
		}
	}
	rows := make([]backupProxy, 0, len(in))
	for _, p := range in {
		bp := backupProxy{Proxy: model.Proxy{
			Hostname: p.Hostname, Enabled: p.Enabled, GateMode: p.GateMode,
			Fingerprint: p.Fingerprint, BotLevel: p.BotLevel, Maintenance: p.Maintenance, WAFMode: p.WAFMode,
			LBPolicy: p.LBPolicy, HealthPath: p.HealthPath, HealthExpect: p.HealthExpect,
			HealthInterval: p.HealthInterval, HealthFailAfter: p.HealthFailAfter,
			MaxInflight: p.MaxInflight, MaxInflightPerClient: p.MaxInflightClient,
		}}
		known := true
		if p.WAFProfile != "" {
			if id, ok := wafID[p.WAFProfile]; ok {
				bp.Proxy.ProfileID = &id
			} else {
				problems = append(problems, "proxy "+p.Hostname+": unknown WAF profile "+p.WAFProfile)
				known = false
			}
		}
		if p.ProtectionProfile != "" {
			if id, ok := protectionID[p.ProtectionProfile]; ok {
				bp.Proxy.ProtectionProfileID = &id
			} else {
				problems = append(problems, "proxy "+p.Hostname+": unknown protection profile "+p.ProtectionProfile)
				known = false
			}
		}
		if !known {
			continue
		}
		for _, u := range p.Upstreams {
			bp.Upstreams = append(bp.Upstreams, model.Upstream{URL: u.URL, Weight: u.Weight, Enabled: u.Enabled, MaxConns: u.MaxConns})
		}
		for _, r := range p.Routes {
			bp.Routes = append(bp.Routes, model.Route{Kind: r.Kind, Match: r.Match, Target: r.Target, StripPrefix: r.StripPrefix})
		}
		rows = append(rows, bp)
	}
	return s.applyProxies(rows, problems)
}

// linkConfigProxyAccessProfiles attaches access profiles after they exist.
func (s *Server) linkConfigProxyAccessProfiles(in []configProxy, problems []string) {
	accessID := map[string]int64{}
	if list, err := s.st.ListAccessProfiles(); err == nil {
		for _, a := range list {
			accessID[a.Name] = a.ID
		}
	}
	for _, p := range in {
		if p.AccessProfile == "" {
			continue
		}
		id, ok := accessID[p.AccessProfile]
		if !ok {
			problems = append(problems, "proxy "+p.Hostname+": unknown access profile "+p.AccessProfile)
			continue
		}
		proxy, err := s.st.ProxyByHost(strings.ToLower(strings.TrimSpace(p.Hostname)))
		if err != nil {
			continue
		}
		proxy.AccessProfileID = &id
		if err := s.st.UpdateProxy(proxy); err != nil {
			problems = append(problems, "proxy "+p.Hostname+": "+err.Error())
		}
	}
}

// applyAccessProfiles resolves the names in the document against profiles,
// lists and policies that already exist or were imported just before it.
func (s *Server) applyAccessProfiles(in []configAccessProfile, problems []string) (int, []string) {
	existing := map[string]bool{}
	if list, err := s.st.ListAccessProfiles(); err == nil {
		for _, a := range list {
			existing[a.Name] = true
		}
	}
	wafID := map[string]int64{}
	if list, err := s.st.ListProfiles(); err == nil {
		for _, p := range list {
			wafID[p.Name] = p.ID
		}
	}
	protectionID := map[string]int64{}
	if list, err := s.st.ListProtectionProfiles(); err == nil {
		for _, p := range list {
			protectionID[p.Name] = p.ID
		}
	}
	listID := map[string]int64{}
	if list, err := s.st.ListAccessLists(); err == nil {
		for _, l := range list {
			listID[l.Name] = l.ID
		}
	}
	policyID := map[string]int64{}
	if list, err := s.st.ListPolicies(); err == nil {
		for _, p := range list {
			policyID[strings.TrimSpace(p.Kind+" "+p.Value)] = p.ID
		}
	}

	added := 0
	for _, a := range in {
		name := strings.TrimSpace(a.Name)
		if name == "" {
			problems = append(problems, "access profile: missing name")
			continue
		}
		if existing[name] {
			problems = append(problems, "access profile "+name+": already exists, skipped")
			continue
		}
		bundle := model.AccessProfile{Name: name}
		for _, list := range a.Lists {
			id, ok := listID[list]
			if !ok {
				problems = append(problems, "access profile "+name+": unknown list "+list)
				continue
			}
			bundle.ListIDs = append(bundle.ListIDs, id)
		}
		if a.WAFProfile != "" {
			id, ok := wafID[a.WAFProfile]
			if !ok {
				problems = append(problems, "access profile "+name+": unknown WAF profile "+a.WAFProfile)
			} else {
				bundle.WAFProfileID = &id
			}
		}
		if a.ProtectionProfile != "" {
			id, ok := protectionID[a.ProtectionProfile]
			if !ok {
				problems = append(problems, "access profile "+name+": unknown protection profile "+a.ProtectionProfile)
			} else {
				bundle.ProtectionProfileID = &id
			}
		}
		for _, rule := range a.Rules {
			id, ok := policyID[rule.Policy]
			if !ok {
				problems = append(problems, "access profile "+name+": unknown policy "+rule.Policy)
				continue
			}
			role := rule.Role
			if role != model.AccessRoleAllow && role != model.AccessRoleDeny {
				role = model.AccessRoleInherit
			}
			bundle.Rules = append(bundle.Rules, model.AccessRule{PolicyID: id, Role: role})
		}
		if err := s.st.CreateAccessProfile(&bundle); err != nil {
			problems = append(problems, "access profile "+name+": "+err.Error())
			continue
		}
		existing[name] = true
		added++
	}
	return added, problems
}
