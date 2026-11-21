package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	updatepkg "github.com/kenhermesagent-lab/waf-proxy-docker/internal/updates"
)

type applyUpdateRequest struct {
	Package string `json:"package"`
}

func (s *Server) getUpdates(w http.ResponseWriter, r *http.Request) {
	if s.updates == nil {
		writeJSON(w, http.StatusOK, updatepkg.Snapshot{
			Available: false,
			Reason:    "The host update manager is not configured.",
			Packages:  []updatepkg.Package{},
		})
		return
	}
	writeJSON(w, http.StatusOK, s.updates.Snapshot(r.Context()))
}

func (s *Server) checkUpdates(w http.ResponseWriter, r *http.Request) {
	if s.updates == nil {
		writeError(w, http.StatusConflict, "host package updates are unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	snap, err := s.updates.Check(ctx)
	if err != nil {
		writeUpdateError(w, err)
		return
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "updates.check", "package index refreshed", clientIP(r))
	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) applyUpdate(w http.ResponseWriter, r *http.Request) {
	if s.updates == nil {
		writeError(w, http.StatusConflict, "host package updates are unavailable")
		return
	}
	var req applyUpdateRequest
	if err := decode(r, &req); err != nil || strings.TrimSpace(req.Package) == "" {
		writeError(w, http.StatusBadRequest, "package is required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	res, err := s.updates.Apply(ctx, strings.TrimSpace(req.Package))
	if err != nil {
		if res.Output != "" {
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error":  err.Error(),
				"output": tail(res.Output, 1200),
			})
			return
		}
		writeUpdateError(w, err)
		return
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "updates.apply", req.Package, clientIP(r))
	writeJSON(w, http.StatusOK, res)
}

func writeUpdateError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, updatepkg.ErrUnavailable):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, updatepkg.ErrNotManaged):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeError(w, http.StatusBadGateway, err.Error())
	}
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
