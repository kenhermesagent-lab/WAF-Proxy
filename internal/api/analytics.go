package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// analyticsRange accepts an explicit date range (YYYY-MM-DD or RFC3339), the
// older hours parameter, or defaults to the last 24 hours.
func analyticsRange(r *http.Request) (time.Time, time.Time) {
	q := r.URL.Query()
	now := time.Now().UTC()
	from, to := now.Add(-24*time.Hour), now
	if v := strings.TrimSpace(q.Get("hours")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 2160 {
			from = now.Add(-time.Duration(n) * time.Hour)
		}
	}
	if v := strings.TrimSpace(q.Get("from")); v != "" {
		if t, ok := parseRangeTime(v, false); ok {
			from = t
		}
	}
	if v := strings.TrimSpace(q.Get("to")); v != "" {
		if t, ok := parseRangeTime(v, true); ok {
			to = t
		}
	}
	if from.After(to) {
		from, to = to, from
	}
	if to.Sub(from) > 90*24*time.Hour {
		from = to.Add(-90 * 24 * time.Hour)
	}
	return from, to
}

func parseRangeTime(v string, endOfDay bool) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC(), true
	}
	// Date-only inputs follow the host's configured timezone (TZ in the
	// container), which is what an operator means by "today".
	t, err := time.ParseInLocation("2006-01-02", v, time.Local)
	if err != nil {
		return time.Time{}, false
	}
	if endOfDay {
		return t.Add(24*time.Hour - time.Nanosecond), true
	}
	return t, true
}

func (s *Server) getAnalytics(w http.ResponseWriter, r *http.Request) {
	from, to := analyticsRange(r)
	out, err := s.db(r).AnalyticsRange(from, to)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getUptime(w http.ResponseWriter, r *http.Request) {
	if s.uptime == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"process_uptime_s": 0,
			"targets":          []any{},
			"proxies":          []any{},
			"checked_at":       "",
		})
		return
	}
	snap := s.uptime.Snapshot()
	if s.consoleSite(r) != s.st.SiteID() {
		// The monitor probes every site; a tenant sees only its own backends.
		own := map[int64]bool{}
		if proxies, err := s.db(r).ListProxies(); err == nil {
			for _, p := range proxies {
				own[p.ID] = true
			}
		}
		targets := snap.Targets[:0]
		for _, t := range snap.Targets {
			if own[t.ProxyID] {
				targets = append(targets, t)
			}
		}
		snap.Targets = targets
		proxies := snap.Proxies[:0]
		for _, p := range snap.Proxies {
			if own[p.ProxyID] {
				proxies = append(proxies, p)
			}
		}
		snap.Proxies = proxies
	}
	writeJSON(w, http.StatusOK, snap)
}

// getUptimeHistory serves the latency samples, outages and slow spans behind
// one proxy, which is what the monitor's drawer shows.
func (s *Server) getUptimeHistory(w http.ResponseWriter, r *http.Request) {
	if s.uptime == nil {
		writeJSON(w, http.StatusOK, map[string]any{"targets": []any{}})
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("proxy_id")), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "proxy_id is required")
		return
	}
	proxies, err := s.db(r).ListProxies()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	known := false
	for _, p := range proxies {
		if p.ID == id {
			known = true
			break
		}
	}
	if !known {
		writeError(w, http.StatusNotFound, "unknown proxy")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"targets": s.uptime.History(id), "generated_at": time.Now(),
	})
}

// hoursBefore reads the hours selector, which runs to the 30 days the event log
// keeps, and returns the start of that window.
func hoursBefore(r *http.Request, fallback int) time.Time {
	hours := fallback
	if n, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && n >= 1 && n <= 720 {
		hours = n
	}
	return time.Now().Add(-time.Duration(hours) * time.Hour)
}

// globeSince parses the 1h–30d history selector and falls back to one hour.
func globeSince(r *http.Request) time.Time { return hoursBefore(r, 1) }

// getUtilization serves the hourly host series: load, link rates and the
// request/block counts the event log already keeps, one row per hour.
func (s *Server) getUtilization(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db(r).UtilizationHours(hoursBefore(r, 720))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hours": rows})
}
