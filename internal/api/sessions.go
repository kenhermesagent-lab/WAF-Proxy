package api

import "net/http"

// activeSessions lists the administrators signed in right now, with the address
// and browser each session came from. permissionFor makes it settings.read
// only, and the store never returns a session identifier.
func (s *Server) activeSessions(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	list, err := s.st.ActiveAdminSessions(c.Value)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": list, "count": len(list)})
}
