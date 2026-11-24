package api

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/threatintel"
)

// threatIntelView is the Settings card: whether RDAP is on, whether a key is
// saved, and the allowance the key's own response headers reported.
type threatIntelView struct {
	RDAP       bool               `json:"rdap"`
	Configured bool               `json:"configured"`
	KeyTail    string             `json:"key_tail,omitempty"`
	Quota      *threatintel.Quota `json:"quota,omitempty"`
	Plan       *threatintel.Plan  `json:"plan,omitempty"`
	CacheHours int                `json:"cache_hours"`
}

func (s *Server) getThreatIntel(w http.ResponseWriter, r *http.Request) {
	kv, err := s.st.Settings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	key := threatintel.LoadKey(kv, s.box)
	quota := s.threat.Quota()
	if quota == nil {
		quota = threatintel.DecodeQuota(kv[threatintel.KeyQuota])
	}
	view := threatIntelView{
		RDAP:       true,
		Configured: key != "",
		Quota:      quota,
		CacheHours: int(threatintel.TTL / time.Hour),
	}
	if key != "" {
		view.KeyTail = keyTail(key)
	}
	if quota != nil {
		view.Plan = threatintel.PlanFor(quota.Limit)
	}
	writeJSON(w, http.StatusOK, view)
}

// putThreatIntel saves or clears the AbuseIPDB key. The key is checked against
// the API before it is stored: one lookup proves it works and reports the real
// allowance, which is what the card shows instead of a guessed plan.
func (s *Server) putThreatIntel(w http.ResponseWriter, r *http.Request) {
	if !s.requireHostConsole(w, r, "the threat-intelligence key") {
		return
	}
	var in struct {
		Key *string `json:"abuseipdb_key"`
	}
	if err := decode(r, &in); err != nil || in.Key == nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	key := strings.TrimSpace(*in.Key)
	kv, err := s.st.Settings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	sess := sessionFrom(r)
	if key == "" {
		if err := s.st.SetSettings(map[string]string{threatintel.KeyKey: "", threatintel.KeyQuota: ""}); err != nil {
			writeError(w, http.StatusInternalServerError, "cannot save settings")
			return
		}
		s.threat.Reset()
		s.db(r).AddAudit(sess.Username, "threatintel.key", "AbuseIPDB key removed", clientIP(r))
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	if !threatintel.ValidKey(key) {
		writeError(w, http.StatusBadRequest, "that does not look like an AbuseIPDB key: paste the full value from your API page")
		return
	}
	// A different key invalidates every cached answer: they were bought with the
	// old allowance and may belong to another account.
	if old := threatintel.LoadKey(kv, s.box); old != key {
		s.threat.Reset()
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	probe, _ := s.threat.Lookup(ctx, threatintel.LocalIP(), key)
	if probe.Abuse != nil && strings.Contains(probe.Abuse.Error, "refused the key") {
		writeError(w, http.StatusBadRequest, "AbuseIPDB refused that key; copy it again from your account's API page")
		return
	}
	sealed, err := threatintel.SealKey(s.box, key)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot seal the key")
		return
	}
	next := map[string]string{threatintel.KeyKey: sealed}
	if probe.Quota != nil {
		next[threatintel.KeyQuota] = threatintel.EncodeQuota(probe.Quota)
	}
	if err := s.st.SetSettings(next); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot save settings")
		return
	}
	s.db(r).AddAudit(sess.Username, "threatintel.key", "AbuseIPDB key saved", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// lookupThreatIntel answers the source drawer: RDAP for the network and, when a
// key is configured, the AbuseIPDB report. Results are cached for six hours.
func (s *Server) lookupThreatIntel(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		writeError(w, http.StatusBadRequest, "not an IP address")
		return
	}
	kv, err := s.st.Settings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	res, err := s.threat.Lookup(ctx, addr.String(), threatintel.LoadKey(kv, s.box))
	if err != nil {
		writeError(w, http.StatusBadGateway, "lookup failed: "+err.Error())
		return
	}
	// Keep the last quota block so the card still shows the allowance after a
	// restart, even when the console is idle.
	if res.Quota != nil && !res.Cached {
		_ = s.st.SetSettings(map[string]string{threatintel.KeyQuota: threatintel.EncodeQuota(res.Quota)})
	}
	writeJSON(w, http.StatusOK, res)
}

// keyTail is the only part of a saved key the console ever sees.
func keyTail(key string) string {
	if len(key) <= 4 {
		return "••••"
	}
	return "••••" + key[len(key)-4:]
}
