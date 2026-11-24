package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/bundle"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// bundleView is one installed pack with the modes its profiles give it.
type bundleView struct {
	bundle.BundleStatus
	Modes map[string]int `json:"modes"`
}

// providerView is one signed channel as the console shows it.
type providerView struct {
	Name       string  `json:"name"`
	Configured bool    `json:"configured"`
	URL        string  `json:"url,omitempty"`
	KeyID      string  `json:"key_id,omitempty"`
	LastCheck  *string `json:"last_check,omitempty"`
	NextCheck  *string `json:"next_check,omitempty"`
	Sequence   int64   `json:"sequence"`
	Error      string  `json:"error,omitempty"`
}

type bundleSnapshot struct {
	// Configured is true when at least one provider can fetch; the console
	// keeps its empty state on this rather than on a single channel URL.
	Configured bool           `json:"configured"`
	Providers  []providerView `json:"providers"`
	Bundles    []bundleView   `json:"bundles"`
}

// SetBundles attaches the installed signature packs. A server built without a
// runtime leaves this nil, and the endpoints then report the channel as
// unconfigured instead of panicking.
func (s *Server) SetBundles(m *bundle.Manager) { s.bundles = m }

// listBundles reports every provider and installed pack. Modes are counted
// across profiles, because a bundle mode is a profile setting, never a global
// switch.
func (s *Server) listBundles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.bundleSnapshot(r))
}

// checkBundles refreshes one provider when ?provider= names it, otherwise all
// of them. Providers are independent, so a failure on one still returns the
// snapshot with the other packs in place.
func (s *Server) checkBundles(w http.ResponseWriter, r *http.Request) {
	if !s.requireHostConsole(w, r, "the signature bundle channel") {
		return
	}
	if s.bundles == nil || !s.bundles.Enabled() {
		writeError(w, http.StatusConflict, "no signed bundle channel is configured")
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("provider"))
	if name != "" && !s.bundles.HasProvider(name) {
		writeError(w, http.StatusBadRequest, "unknown bundle provider")
		return
	}
	detail := "checked"
	var err error
	if name != "" {
		detail = "checked " + name
		err = s.bundles.CheckProvider(r.Context(), name)
	} else {
		err = s.bundles.Check(r.Context())
	}
	sess := sessionFrom(r)
	if err != nil {
		detail = err.Error()
	}
	s.db(r).AddAudit(sess.Username, "bundle.check", detail, clientIP(r))
	writeJSON(w, http.StatusOK, s.bundleSnapshot(r))
}

// enableBundle switches one pack on or off. A disabled pack keeps its files
// and version, so re-enabling it needs no download.
func (s *Server) enableBundle(w http.ResponseWriter, r *http.Request) {
	if !s.requireHostConsole(w, r, "the signature bundle channel") {
		return
	}
	if s.bundles == nil {
		writeError(w, http.StatusConflict, "no bundle manager is running")
		return
	}
	var in struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.bundles.SetEnabled(strings.TrimSpace(in.Name), in.Enabled); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sess := sessionFrom(r)
	action := "bundle.disable"
	if in.Enabled {
		action = "bundle.enable"
	}
	s.st.AddAudit(sess.Username, action, in.Name, clientIP(r))
	writeJSON(w, http.StatusOK, s.bundleSnapshot(r))
}

// saveBundleProvider adds or replaces one channel from the console. The list
// is stored in the settings table, which takes over from the environment once
// the first edit is saved here.
func (s *Server) saveBundleProvider(w http.ResponseWriter, r *http.Request) {
	if !s.requireHostConsole(w, r, "the signature bundle channel") {
		return
	}
	if s.bundles == nil {
		writeError(w, http.StatusConflict, "no bundle manager is running")
		return
	}
	var in struct {
		Name      string `json:"name"`
		URL       string `json:"url"`
		PublicKey string `json:"public_key"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	list := s.bundles.Providers()
	replaced := false
	for i := range list {
		if list[i].Name == strings.TrimSpace(in.Name) {
			list[i] = bundle.Provider{Name: in.Name, URL: in.URL, PublicKey: in.PublicKey}
			replaced = true
		}
	}
	if !replaced {
		list = append(list, bundle.Provider{Name: in.Name, URL: in.URL, PublicKey: in.PublicKey})
	}
	if err := s.bundles.SetProviders(list); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.st.SetSetting(bundle.SettingsKey, bundle.MarshalProviders(list)); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "bundle.provider", "saved "+strings.TrimSpace(in.Name), clientIP(r))
	writeJSON(w, http.StatusOK, s.bundleSnapshot(r))
}

// deleteBundleProvider drops one channel. Its installed packs stay on disk and
// keep serving until an administrator disables them.
func (s *Server) deleteBundleProvider(w http.ResponseWriter, r *http.Request) {
	if !s.requireHostConsole(w, r, "the signature bundle channel") {
		return
	}
	if s.bundles == nil {
		writeError(w, http.StatusConflict, "no bundle manager is running")
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	list := s.bundles.Providers()
	kept := list[:0]
	for _, p := range list {
		if p.Name != name {
			kept = append(kept, p)
		}
	}
	if len(kept) == len(list) {
		writeError(w, http.StatusNotFound, "unknown bundle provider")
		return
	}
	if err := s.bundles.SetProviders(kept); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.st.SetSetting(bundle.SettingsKey, bundle.MarshalProviders(kept)); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "bundle.provider", "removed "+name, clientIP(r))
	writeJSON(w, http.StatusOK, s.bundleSnapshot(r))
}

// bundleHits groups the rule IDs the event log already recorded. Nothing extra
// is written per request; this is a query over the WAF stage rows.
func (s *Server) bundleHits(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if raw := r.URL.Query().Get("hours"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "hours must be a positive number")
			return
		}
		if n > 168 {
			n = 168
		}
		hours = n
	}
	hits, err := s.db(r).BundleHits(nowMinus(hours))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	index := map[int]bundle.RuleInfo{}
	if s.bundles != nil {
		index = s.bundles.RuleIndex()
	}
	profiles, _ := s.db(r).ListProfiles()
	rules := make([]BundleHit, 0, len(hits))
	for _, h := range hits {
		info := index[h.RuleID]
		rules = append(rules, BundleHit{
			RuleID: h.RuleID, Provider: info.Provider, Bundle: info.Bundle, Version: info.Version,
			Message: firstNonEmpty(h.Message, info.Message),
			Hits:    h.Hits, Addresses: h.Addresses,
			Blocked: h.Blocked, Logged: h.Logged, LastSeen: h.LastSeen,
			Modes: modeCounts(profiles, info.Bundle),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"hours": hours, "rules": rules})
}

// BundleHit is one bundle rule with its activity and profile modes.
type BundleHit struct {
	RuleID    int    `json:"rule_id"`
	Provider  string `json:"provider,omitempty"`
	Bundle    string `json:"bundle,omitempty"`
	Version   string `json:"version,omitempty"`
	Message   string `json:"message"`
	Hits      int64  `json:"hits"`
	Addresses int64  `json:"addresses"`
	// Blocked and Logged are what the matching requests got, which can differ
	// from the profile modes below when sites run the same bundle differently.
	Blocked  int64          `json:"blocked"`
	Logged   int64          `json:"logged"`
	LastSeen string         `json:"last_seen"`
	Modes    map[string]int `json:"modes"`
}

// modeCounts answers "what does this bundle do on the profiles that use it?".
// A rule with no installed pack is still reported, with an empty map, so a
// removed bundle does not hide its history.
func modeCounts(profiles []model.Profile, name string) map[string]int {
	counts := map[string]int{model.BundleBlock: 0, model.BundleLog: 0, model.BundleOff: 0}
	if name == "" {
		return counts
	}
	for _, p := range profiles {
		counts[p.BundleMode(name)]++
	}
	return counts
}

func (s *Server) bundleSnapshot(r *http.Request) bundleSnapshot {
	if s.bundles == nil {
		return bundleSnapshot{Configured: false, Providers: []providerView{}, Bundles: []bundleView{}}
	}
	st := s.bundles.Status()
	profiles, _ := s.db(r).ListProfiles()
	out := bundleSnapshot{
		Providers: make([]providerView, 0, len(st.Providers)),
		Bundles:   make([]bundleView, 0, len(st.Bundles)),
	}
	for _, p := range st.Providers {
		out.Providers = append(out.Providers, providerView{
			Name: p.Name, Configured: p.Configured, URL: p.URL, KeyID: p.KeyID,
			LastCheck: isoPtr(p.LastCheck), NextCheck: isoPtr(p.NextCheck),
			Sequence: p.Sequence, Error: p.Error,
		})
		if p.Configured {
			out.Configured = true
		}
	}
	for _, b := range st.Bundles {
		out.Bundles = append(out.Bundles, bundleView{BundleStatus: b, Modes: modeCounts(profiles, b.Name)})
	}
	return out
}

// validBundleModes rejects a mode the engine would ignore, and caps the
// number of settings so a crafted profile cannot grow without bound.
func validBundleModes(modes map[string]string) string {
	if len(modes) > 64 {
		return "a profile can set modes for at most 64 bundles"
	}
	for name, mode := range modes {
		name = strings.TrimSpace(name)
		if name == "" || len(name) > 64 {
			return "a bundle name must be 1–64 characters"
		}
		if !model.ValidBundleMode(mode) {
			return "a bundle mode must be off, log or block"
		}
	}
	return ""
}

func isoPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	v := t.UTC().Format(time.RFC3339)
	return &v
}

func nowMinus(hours int) time.Time {
	return time.Now().Add(-time.Duration(hours) * time.Hour)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// bundleModesOrEmpty returns a copy safe to store and to serialise.
func bundleModesOrEmpty(modes map[string]string) map[string]string {
	out := map[string]string{}
	for name, mode := range modes {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		out[name] = mode
	}
	return out
}
