package api

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/anomaly"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// SetAnomaly attaches the detector; without it the endpoints report unavailable.
func (s *Server) SetAnomaly(m *anomaly.Manager) { s.anomaly = m }

func (s *Server) getAnomaly(w http.ResponseWriter, r *http.Request) {
	det := s.anomalyFor(r)
	if det == nil {
		writeError(w, http.StatusServiceUnavailable, "the anomaly detector is not configured")
		return
	}
	events, err := s.db(r).ListAnomalyEvents(200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	cfg, err := det.Config()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	mutes, err := det.Mutes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "config": cfg, "mutes": mutes})
}

func (s *Server) putAnomalySettings(w http.ResponseWriter, r *http.Request) {
	det := s.anomalyFor(r)
	if det == nil {
		writeError(w, http.StatusServiceUnavailable, "the anomaly detector is not configured")
		return
	}
	var in anomaly.Config
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if err := det.Save(in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "anomaly.configure", strconv.FormatBool(in.Enabled), clientIP(r))
	cfg, _ := det.Config()
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) acknowledgeAnomaly(w http.ResponseWriter, r *http.Request) {
	if s.anomalyFor(r) == nil {
		writeError(w, http.StatusServiceUnavailable, "the anomaly detector is not configured")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.db(r).AcknowledgeAnomalyEvent(id, sessionFrom(r).Username); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot acknowledge")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// destination is one configured upstream of a site: where its outbound traffic
// actually goes, the addresses it resolves to, and the whitelist covering it.
type destination struct {
	URL       string   `json:"url"`
	Address   string   `json:"address"`
	Port      string   `json:"port,omitempty"`
	Resolved  []string `json:"resolved,omitempty"`
	Whitelist string   `json:"whitelist,omitempty"`
	Muted     bool     `json:"muted"`
}

// getAnomalyEvent answers the slide-over: one detection and the destinations the
// site behind it sends traffic to.
func (s *Server) getAnomalyEvent(w http.ResponseWriter, r *http.Request) {
	det := s.anomalyFor(r)
	if det == nil {
		writeError(w, http.StatusServiceUnavailable, "the anomaly detector is not configured")
		return
	}
	e := s.anomalyEvent(w, r)
	if e == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"event": e, "destinations": s.destinations(r, det, e.ProxyID)})
}

// muteAnomaly records a destination as expected traffic and clears the open
// outbound spikes it already raised for that site.
func (s *Server) muteAnomaly(w http.ResponseWriter, r *http.Request) {
	det := s.anomalyFor(r)
	if det == nil {
		writeError(w, http.StatusServiceUnavailable, "the anomaly detector is not configured")
		return
	}
	e := s.anomalyEvent(w, r)
	if e == nil {
		return
	}
	var in struct {
		Address string `json:"address"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	in.Address = strings.TrimSpace(in.Address)
	known := false
	for _, d := range s.destinations(r, det, e.ProxyID) {
		if d.Address == in.Address {
			known = true
			break
		}
	}
	if !known {
		writeError(w, http.StatusBadRequest, "that address is not one of this site's upstreams")
		return
	}
	if err := det.AddMute(e.ProxyID, in.Address); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot save the mute")
		return
	}
	sess := sessionFrom(r)
	if _, err := s.db(r).AcknowledgeOpenAnomalies("egress_spike", e.ProxyID, sess.Username); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot clear the open events")
		return
	}
	s.db(r).AddAudit(sess.Username, "anomaly.mute", e.ProxyHost+" → "+in.Address, clientIP(r))
	s.writeMutes(w, det)
}

// unmuteAnomaly forgets an expected destination, so its spikes are detected
// again.
func (s *Server) unmuteAnomaly(w http.ResponseWriter, r *http.Request) {
	det := s.anomalyFor(r)
	if det == nil {
		writeError(w, http.StatusServiceUnavailable, "the anomaly detector is not configured")
		return
	}
	proxyID, err := strconv.ParseInt(r.URL.Query().Get("proxy_id"), 10, 64)
	if err != nil || proxyID == 0 {
		writeError(w, http.StatusBadRequest, "invalid proxy")
		return
	}
	address := strings.TrimSpace(r.URL.Query().Get("address"))
	if address == "" {
		writeError(w, http.StatusBadRequest, "invalid destination")
		return
	}
	if err := det.RemoveMute(proxyID, address); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot remove the mute")
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "anomaly.unmute", address, clientIP(r))
	s.writeMutes(w, det)
}

func (s *Server) writeMutes(w http.ResponseWriter, det *anomaly.Manager) {
	mutes, err := det.Mutes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mutes": mutes})
}

// anomalyEvent resolves the {id} path value, answering the error itself and
// returning nil when the response is already written.
func (s *Server) anomalyEvent(w http.ResponseWriter, r *http.Request) *model.AnomalyEvent {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return nil
	}
	e, err := s.db(r).GetAnomalyEvent(id)
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "no such event")
		return nil
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return nil
	}
	return e
}

// destinations lists a site's upstreams with the addresses they reach and the
// whitelist that covers them. The whitelists are the enabled ip_whitelist
// policies that apply to this site.
func (s *Server) destinations(r *http.Request, det *anomaly.Manager, proxyID int64) []destination {
	ups, err := s.db(r).ListUpstreams(proxyID)
	if err != nil {
		return []destination{}
	}
	mutes, _ := det.Mutes()
	expected := map[string]bool{}
	for _, mu := range mutes {
		if mu.ProxyID == proxyID {
			expected[mu.Address] = true
		}
	}
	rules := s.whitelistRules(r, proxyID)
	out := []destination{}
	for _, up := range ups {
		u, err := url.Parse(up.URL)
		if err != nil || u.Hostname() == "" {
			continue
		}
		d := destination{URL: up.URL, Address: u.Hostname(), Port: u.Port(), Muted: expected[u.Hostname()]}
		d.Resolved = resolveHost(r.Context(), u.Hostname())
		for _, rule := range rules {
			covered := false
			for _, raw := range d.Resolved {
				if a, err := netip.ParseAddr(raw); err == nil && rule.prefix.Contains(a) {
					covered = true
					break
				}
			}
			if covered {
				d.Whitelist = rule.label
				break
			}
		}
		out = append(out, d)
	}
	return out
}

type whitelistRule struct {
	prefix netip.Prefix
	label  string
}

func (s *Server) whitelistRules(r *http.Request, proxyID int64) []whitelistRule {
	policies, err := s.db(r).ListPolicies()
	if err != nil {
		return nil
	}
	out := []whitelistRule{}
	for _, p := range policies {
		if !p.Enabled || p.Kind != model.PolicyIPWhitelist {
			continue
		}
		if p.Scope == "proxy" && (p.ProxyID == nil || *p.ProxyID != proxyID) {
			continue
		}
		for _, part := range strings.Split(p.Value, ",") {
			part = strings.TrimSpace(part)
			prefix, ok := parsePrefix(part)
			if !ok {
				continue
			}
			label := p.Note
			if label == "" {
				label = part
			}
			out = append(out, whitelistRule{prefix: prefix, label: label})
		}
	}
	return out
}

// parsePrefix accepts one address or CIDR, the two forms a whitelist entry takes.
func parsePrefix(s string) (netip.Prefix, bool) {
	if s == "" {
		return netip.Prefix{}, false
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p, err == nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}

// resolveHost turns an upstream host into the addresses it points at: a literal
// is its own answer and a name gets a short, best-effort lookup.
func resolveHost(ctx context.Context, host string) []string {
	if a, err := netip.ParseAddr(host); err == nil {
		return []string{a.Unmap().String()}
	}
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, a := range addrs {
		if len(out) == 4 {
			break
		}
		out = append(out, a.Unmap().String())
	}
	return out
}
