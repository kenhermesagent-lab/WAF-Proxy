package api

import "net/http"

// mePrefs reads and writes the caller's own console preferences. The user comes
// from the session, never the body, so one administrator cannot touch another's.
func (s *Server) mePrefs(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if r.Method == http.MethodGet {
		prefs, err := s.db(r).Prefs(sess.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		writeJSON(w, http.StatusOK, prefs)
		return
	}
	var in struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := decode(r, &in); err != nil || in.Key == "" || len(in.Key) > 64 || len(in.Value) > 512 {
		writeError(w, http.StatusBadRequest, "key and a value under 512 bytes are required")
		return
	}
	if err := s.db(r).SetPref(sess.UserID, in.Key, in.Value); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
