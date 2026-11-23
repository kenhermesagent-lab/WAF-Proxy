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

type bundleSnapshot struct {
	Configured bool         `json:"configured"`
	URL        string       `json:"url,omitempty"`
	KeyID      string       `json:"key_id,omitempty"`
	LastCheck  *string      `json:"last_check,omitempty"`
	NextCheck  *string      `json:"next_check,omitempty"`
	Sequence   int64        `json:"sequence"`
	Error      string       `json:"error,omitempty"`
	Bundles    []bundleView `json:"bundles"`
}

// SetBundles attaches the installed signature packs. A server built without a
// runtime leaves this nil, and the endpoints then report the channel as
// unconfigured instead of panicking.
func (s *Server) SetBundles(m *bundle.Manager) { s.bundles = m }

// listBundles reports the channel and every installed pack. Modes are counted
// across profiles, because a bundle mode is a profile setting, never a global
// switch.
func (s *Server) listBundles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.bundleSnapshot())
}

func (s *Server) checkBundles(w http.ResponseWriter, r *http.Request) {
	if s.bundles == nil || !s.bundles.Enabled() {
		writeError(w, http.StatusConflict, "no signed bundle channel is configured")
		return
	}
	err := s.bundles.Check(r.Context())
	sess := sessionFrom(r)
	detail := "checked"
	if err != nil {
		detail = err.Error()
	}
	s.st.AddAudit(sess.Username, "bundle.check", detail, clientIP(r))
	writeJSON(w, http.StatusOK, s.bundleSnapshot())
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
	hits, err := s.st.BundleHits(nowMinus(hours))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	index := map[int]bundle.RuleInfo{}
	if s.bundles != nil {
		index = s.bundles.RuleIndex()
	}
	profiles, _ := s.st.ListProfiles()
	rules := make([]BundleHit, 0, len(hits))
	for _, h := range hits {
		info := index[h.RuleID]
		rules = append(rules, BundleHit{
			RuleID: h.RuleID, Bundle: info.Bundle, Version: info.Version,
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

func (s *Server) bundleSnapshot() bundleSnapshot {
	if s.bundles == nil {
		return bundleSnapshot{Configured: false, Bundles: []bundleView{}}
	}
	st := s.bundles.Status()
	profiles, _ := s.st.ListProfiles()
	out := bundleSnapshot{
		Configured: st.Configured, URL: st.URL, KeyID: st.KeyID,
		Sequence: st.Sequence, Error: st.Error, Bundles: []bundleView{},
	}
	out.LastCheck = isoPtr(st.LastCheck)
	out.NextCheck = isoPtr(st.NextCheck)
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
