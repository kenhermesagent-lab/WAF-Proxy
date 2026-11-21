package api

import (
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// gateFailureView is one row of the Statistics page's failed-login table: who
// was tried, from where, against which site, and whether the address is already
// blocked.
type gateFailureView struct {
	IP               string    `json:"ip"`
	Username         string    `json:"username"`
	ProxyID          int64     `json:"proxy_id"`
	ProxyHost        string    `json:"proxy_host,omitempty"`
	Attempts         int       `json:"attempts"`
	First            time.Time `json:"first"`
	Last             time.Time `json:"last"`
	Blocked          bool      `json:"blocked"`
	BlockedPermanent bool      `json:"blocked_permanent"`
	BlockedReason    string    `json:"blocked_reason,omitempty"`
	BlockedSource    string    `json:"blocked_source,omitempty"`
}

// listGateFailures reports failed access-gate logins in the requested range,
// aggregated by address, username and proxy so a bot spraying one password
// across a list of accounts stays readable.
func (s *Server) listGateFailures(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	now := time.Now()
	from := dayParam(q.Get("from"), now.AddDate(0, 0, -6))
	to := dayParam(q.Get("to"), now).Add(24 * time.Hour)

	rows, err := s.st.GateFailureReport(from, to, 200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	hosts := map[int64]string{}
	if proxies, err := s.st.ListProxies(); err == nil {
		for _, p := range proxies {
			hosts[p.ID] = p.Hostname
		}
	}
	out := make([]gateFailureView, 0, len(rows))
	for _, row := range rows {
		v := gateFailureView{
			IP: row.IP, Username: row.Username, ProxyID: row.ProxyID,
			ProxyHost: hosts[row.ProxyID], Attempts: row.Attempts,
			First: row.First, Last: row.Last,
		}
		if addr, err := netip.ParseAddr(row.IP); err == nil {
			if rec, ok := s.bans.Match(addr); ok {
				v.Blocked = true
				v.BlockedPermanent = rec.Permanent
				v.BlockedReason = rec.Reason
				v.BlockedSource = rec.Source
			}
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"failures": out,
		"from":     from.UTC().Format(time.RFC3339),
		"to":       to.UTC().Format(time.RFC3339),
	})
}

// dayParam accepts the date inputs the Statistics page sends and falls back to
// def when the parameter is missing or malformed.
func dayParam(v string, def time.Time) time.Time {
	if t, err := time.Parse("2006-01-02", strings.TrimSpace(v)); err == nil {
		return t
	}
	return def
}
