package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

const (
	maxViewName  = 64
	maxViewQuery = 2000
)

// listLogViews returns the views every log reader shares.
func (s *Server) listLogViews(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListLogViews()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"views": list})
}

// saveLogView stores a named filter for the whole team. The permission check
// runs before this handler: only a role that may write traffic gets here.
func (s *Server) saveLogView(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" || len(name) > maxViewName {
		writeError(w, http.StatusBadRequest, "view name must be 1-64 characters")
		return
	}
	var in struct {
		Query string `json:"query"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	query := strings.TrimSpace(in.Query)
	if len(query) > maxViewQuery {
		writeError(w, http.StatusBadRequest, "view filters are too long")
		return
	}
	user := sessionFrom(r).Username
	if err := s.st.SaveLogView(name, query, user); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	s.st.AddAudit(user, "logs.view.save", name, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"name": name})
}

// deleteLogView removes a shared view by name.
func (s *Server) deleteLogView(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		writeError(w, http.StatusBadRequest, "a view name is required")
		return
	}
	// Removing a view that is already gone is the caller's intended end state,
	// so a missing row is not an error.
	err := s.st.DeleteLogView(name)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if err == nil {
		s.st.AddAudit(sessionFrom(r).Username, "logs.view.delete", name, clientIP(r))
	}
	w.WriteHeader(http.StatusNoContent)
}
