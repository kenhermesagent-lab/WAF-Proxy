package api

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// eventFilterFromQuery parses the shared log/CSV/IP filter set. Unknown or
// malformed values are ignored rather than rejected so a bookmarked URL keeps
// working after a field changes.
func eventFilterFromQuery(q url.Values) store.EventFilter {
	now := time.Now()
	f := store.EventFilter{Limit: 100, From: now.Add(-24 * time.Hour), To: now}
	if v := q.Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 8760 {
			f.From = now.Add(-time.Duration(n) * time.Hour)
		}
	}
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
	f.SrcIP = strings.TrimSpace(q.Get("ip"))
	f.Country = strings.ToUpper(strings.TrimSpace(q.Get("country")))
	f.Stage = strings.TrimSpace(q.Get("stage"))
	f.Action = strings.TrimSpace(q.Get("action"))
	f.Host = strings.TrimSpace(q.Get("host"))
	f.BlockedOnly = q.Get("blocked") == "1"
	if v := q.Get("proxy_id"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			f.ProxyID = &n
		}
	}
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
	return f
}

var csvHeader = []string{
	"time", "src_ip", "country", "asn", "host", "method", "path", "status",
	"action", "stage", "rule_id", "rule_msg", "bytes_in", "bytes_out", "latency_ms", "user_agent",
}

// csvSafe neutralises spreadsheet formula injection. Exported values are
// attacker-controlled (paths, user agents), so a leading =, +, - or @ must not
// execute when the file is opened in Excel.
func csvSafe(v string) string {
	if v == "" {
		return ""
	}
	// Leading whitespace is stripped by some spreadsheet importers, so check the
	// first meaningful character as well as the raw first byte.
	trimmed := strings.TrimLeft(v, " \t\r")
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + v
	}
	return v
}

func (s *Server) exportEventsCSV(w http.ResponseWriter, r *http.Request) {
	f := eventFilterFromQuery(r.URL.Query())
	limit := 10000
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=\"wafproxy-events-%s.csv\"", time.Now().UTC().Format("20060102-150405")))
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write(csvHeader)
	flusher, canFlush := w.(http.Flusher)
	n := 0
	if err := s.st.EachEvent(f, limit, func(e model.Event) error {
		if err := cw.Write([]string{
			e.TS.UTC().Format(time.RFC3339), e.SrcIP, csvSafe(e.Country), strconv.Itoa(e.ASN), csvSafe(e.Host),
			csvSafe(e.Method), csvSafe(e.Path), strconv.Itoa(e.Status), csvSafe(e.Action), csvSafe(e.Stage),
			csvSafe(e.RuleID), csvSafe(e.RuleMsg), strconv.FormatInt(e.BytesIn, 10), strconv.FormatInt(e.BytesOut, 10),
			strconv.FormatInt(e.LatencyMS, 10), csvSafe(e.UA),
		}); err != nil {
			return err
		}
		// Flush in blocks so a long export reaches the client instead of sitting
		// in a proxy buffer until the response ends.
		if n++; canFlush && n%500 == 0 {
			cw.Flush()
			flusher.Flush()
		}
		return cw.Error()
	}); err != nil {
		// The 200 and header row are already on the wire, so the download is
		// simply truncated; log it rather than corrupting the status line.
		s.log.Warn("csv export aborted", "rows", n, "err", err)
	}
}

// banInfo is the ban state attached to an IP summary.
type banInfo struct {
	Banned     bool       `json:"banned"`
	Permanent  bool       `json:"permanent"`
	BanID      int64      `json:"ban_id,omitempty"`
	BanReason  string     `json:"ban_reason,omitempty"`
	BanSource  string     `json:"ban_source,omitempty"`
	BanExpires *time.Time `json:"ban_expires,omitempty"`
}

// ipView is an IP summary with the active ban, if any.
type ipView struct {
	store.IPSummary
	banInfo
}

func (s *Server) banIndex() map[string]model.Ban {
	out := map[string]model.Ban{}
	list, err := s.bans.List(false)
	if err != nil {
		return out
	}
	for _, b := range list {
		out[b.CIDR] = b
	}
	return out
}

func (s *Server) banView(ip string, index map[string]model.Ban) banInfo {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return banInfo{}
	}
	rec, ok := s.bans.Match(addr)
	if !ok {
		return banInfo{}
	}
	info := banInfo{Banned: true, Permanent: rec.Permanent, BanReason: rec.Reason,
		BanSource: rec.Source, BanExpires: rec.ExpiresAt}
	if b, found := index[rec.CIDR]; found {
		info.BanID = b.ID
	}
	return info
}

func (s *Server) listIPs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := eventFilterFromQuery(q)
	limit := 50
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	list, err := s.st.IPSummaries(f, q.Get("q"), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	index := s.banIndex()
	out := make([]ipView, 0, len(list))
	for _, sum := range list {
		out = append(out, ipView{IPSummary: sum, banInfo: s.banView(sum.IP, index)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ips": out, "from": f.From, "to": f.To})
}

func (s *Server) getIP(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.PathValue("ip"))
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid IP address")
		return
	}
	ip = addr.String()
	f := eventFilterFromQuery(r.URL.Query())
	sum, err := s.st.IPSummary(ip, f.From, f.To)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	events, total, err := s.st.QueryEvents(store.EventFilter{From: f.From, To: f.To, SrcIP: ip, Limit: 100})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	v := ipView{IPSummary: sum, banInfo: s.banView(ip, s.banIndex())}
	writeJSON(w, http.StatusOK, map[string]any{
		"summary": v, "events": events, "total": total, "from": f.From, "to": f.To,
	})
}

func (s *Server) crowdsecStatus(w http.ResponseWriter, r *http.Request) {
	if s.cs == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"configured": false, "lapi_configured": strings.TrimSpace(s.cfg.CrowdSecURL) != "",
			"mode": "stream", "applied": 0, "last_error": "",
		})
		return
	}
	writeJSON(w, http.StatusOK, s.cs.Status())
}
