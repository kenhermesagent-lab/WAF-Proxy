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

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// configDoc is the declarative half of a backup. Bans and feeds are live state,
// so they stay in the JSON backup and out of the YAML configuration.
type configDoc struct {
	Version            string                    `json:"version"`
	ExportedAt         time.Time                 `json:"exported_at"`
	Note               string                    `json:"note"`
	Settings           map[string]string         `json:"settings"`
	WAFProfiles        []model.Profile           `json:"waf_profiles"`
	ProtectionProfiles []model.ProtectionProfile `json:"protection_profiles"`
	AccessLists        []model.AccessList        `json:"access_lists"`
	AccessProfiles     []configAccessProfile     `json:"access_profiles"`
	Proxies            []backupProxy             `json:"proxies"`
	Policies           []model.Policy            `json:"policies"`
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
	proxies, err := s.st.ListProxies()
	if err != nil {
		return configDoc{}, err
	}
	hosts := make([]backupProxy, 0, len(proxies))
	for _, p := range proxies {
		bp := backupProxy{Proxy: p}
		bp.Upstreams, _ = s.st.ListUpstreams(p.ID)
		bp.Routes, _ = s.st.ListRoutes(p.ID)
		hosts = append(hosts, bp)
	}
	// Builtins are seeded on every install, so only operator profiles travel.
	wafAll, _ := s.st.ListProfiles()
	waf := make([]model.Profile, 0, len(wafAll))
	for _, p := range wafAll {
		if !p.Builtin {
			waf = append(waf, p)
		}
	}
	protectionAll, _ := s.st.ListProtectionProfiles()
	protection := make([]model.ProtectionProfile, 0, len(protectionAll))
	for _, p := range protectionAll {
		if !p.Builtin {
			protection = append(protection, p)
		}
	}
	lists, _ := s.st.ListAccessLists()
	access, _ := s.st.ListAccessProfiles()
	policies, _ := s.st.ListPolicies()

	wafName := map[int64]string{}
	for _, p := range waf {
		wafName[p.ID] = p.Name
	}
	protectionName := map[int64]string{}
	for _, p := range protection {
		protectionName[p.ID] = p.Name
	}
	listName := map[int64]string{}
	for _, l := range lists {
		listName[l.ID] = l.Name
	}
	policyRef := map[int64]string{}
	for _, p := range policies {
		policyRef[p.ID] = strings.TrimSpace(p.Kind + " " + p.Value)
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

	return configDoc{
		Version: "1.0", ExportedAt: time.Now().UTC(), Settings: safe,
		WAFProfiles: waf, ProtectionProfiles: protection, AccessLists: lists,
		AccessProfiles: profiles, Proxies: hosts, Policies: policies,
		Note: "Declarative configuration only; bans, feeds, certificates and secrets are not included. " +
			"Access profiles name their lists, WAF profiles and protection profiles. Proxy and policy rows keep " +
			"the numeric ids this install used.",
	}, nil
}

// exportConfigYAML renders the declarative configuration as readable YAML.
func (s *Server) exportConfigYAML(w http.ResponseWriter, _ *http.Request) {
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
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="wafproxy.yaml"`)
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
	result["policies"], problems = s.applyPolicies(in.Policies, problems)
	result["access_profiles"], problems = s.applyAccessProfiles(in.AccessProfiles, problems)
	result["proxies"], problems = s.applyProxies(in.Proxies, problems)

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

func (s *Server) applyAccessLists(in []model.AccessList, problems []string) (int, []string) {
	existing := map[string]bool{}
	if list, err := s.st.ListAccessLists(); err == nil {
		for _, l := range list {
			existing[l.Name] = true
		}
	}
	added := 0
	for _, l := range in {
		name := strings.TrimSpace(l.Name)
		if name == "" {
			problems = append(problems, "access list: missing name")
			continue
		}
		if l.Kind != model.ListKindBlock && l.Kind != model.ListKindAllow {
			problems = append(problems, "access list "+name+": kind must be blocklist or whitelist")
			continue
		}
		if existing[name] {
			problems = append(problems, "access list "+name+": already exists, skipped")
			continue
		}
		l.ID, l.Name, l.CreatedAt = 0, name, time.Time{}
		if err := s.st.CreateAccessList(&l); err != nil {
			problems = append(problems, "access list "+name+": "+err.Error())
			continue
		}
		existing[name] = true
		added++
	}
	return added, problems
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
