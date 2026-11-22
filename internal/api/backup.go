package api

import (
	"context"
	"net/http"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/backup"
)

// StartBackup runs the backup schedule until the process stops.
func (s *Server) StartBackup(ctx context.Context) {
	if s.backup != nil {
		go s.backup.Start(ctx)
	}
}

func (s *Server) getBackup(w http.ResponseWriter, r *http.Request) {
	if s.backup == nil {
		writeError(w, http.StatusServiceUnavailable, "the backup manager is not configured")
		return
	}
	cfg, err := s.backup.Config()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	// The decrypted password and passphrase stay server-side; the console only
	// learns whether one is stored.
	cfg.Password = ""
	cfg.Passphrase = ""
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "status": s.backup.Status()})
}

func (s *Server) putBackup(w http.ResponseWriter, r *http.Request) {
	if s.backup == nil {
		writeError(w, http.StatusServiceUnavailable, "the backup manager is not configured")
		return
	}
	var in backup.Config
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if msg := in.Validate(); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if err := s.backup.Save(in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "backup.configure", in.Transport, clientIP(r))
	cfg, _ := s.backup.Config()
	cfg.Password = ""
	cfg.Passphrase = ""
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "status": s.backup.Status()})
}

func (s *Server) runBackup(w http.ResponseWriter, r *http.Request) {
	if s.backup == nil {
		writeError(w, http.StatusServiceUnavailable, "the backup manager is not configured")
		return
	}
	if _, err := s.backup.RunNow(); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	status := s.backup.Status()
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "backup.run", status.LastFile, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"status": status})
}
