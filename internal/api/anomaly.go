package api

import (
	"net/http"
	"strconv"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/anomaly"
)

// SetAnomaly attaches the detector; without it the endpoints report unavailable.
func (s *Server) SetAnomaly(m *anomaly.Manager) { s.anomaly = m }

func (s *Server) getAnomaly(w http.ResponseWriter, r *http.Request) {
	if s.anomaly == nil {
		writeError(w, http.StatusServiceUnavailable, "the anomaly detector is not configured")
		return
	}
	events, err := s.db(r).ListAnomalyEvents(200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	cfg, err := s.anomaly.Config()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "config": cfg})
}

func (s *Server) putAnomalySettings(w http.ResponseWriter, r *http.Request) {
	if s.anomaly == nil {
		writeError(w, http.StatusServiceUnavailable, "the anomaly detector is not configured")
		return
	}
	var in anomaly.Config
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if err := s.anomaly.Save(in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "anomaly.configure", strconv.FormatBool(in.Enabled), clientIP(r))
	cfg, _ := s.anomaly.Config()
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) acknowledgeAnomaly(w http.ResponseWriter, r *http.Request) {
	if s.anomaly == nil {
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
