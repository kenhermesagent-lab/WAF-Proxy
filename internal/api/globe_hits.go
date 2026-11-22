package api

import (
	"net/http"
	"strconv"
	"time"
)

// getGlobeHits returns individual blocked requests, newest first, for the
// globe's live arc feed. Without a cursor it covers the last minute.
func (s *Server) getGlobeHits(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Add(-time.Minute)
	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			since = t
		}
	}
	limit := 60
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	hits, err := s.st.RecentHits(since, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, hits)
}
