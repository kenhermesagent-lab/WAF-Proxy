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

func (s *Server) applyAppUpdate(w http.ResponseWriter, r *http.Request) {
	if s.updates == nil {
		writeError(w, http.StatusConflict, "application updates are unavailable")
		return
	}
	err := s.updates.StartAppUpdate(func() {
		if s.restartFn == nil {
			return
		}
		go func() {
			time.Sleep(1500 * time.Millisecond)
			s.restartFn()
		}()
	})
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "updates.apply_app", "application rebuild requested", clientIP(r))
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "updating"})
}

type configureAppRequest struct {
	Path string `json:"path"`
}

// configureAppUpdate records the checkout the root helper rebuilds, for an
// install whose directory differs from what install.sh recorded.
func (s *Server) configureAppUpdate(w http.ResponseWriter, r *http.Request) {
	if s.updates == nil {
		writeError(w, http.StatusConflict, "application updates are unavailable")
		return
	}
	var req configureAppRequest
	if err := decode(r, &req); err != nil || strings.TrimSpace(req.Path) == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := s.updates.ConfigureApp(ctx, strings.TrimSpace(req.Path)); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "updates.configure_app", strings.TrimSpace(req.Path), clientIP(r))
	writeJSON(w, http.StatusOK, s.updates.Snapshot(r.Context()))
}

func (s *Server) getAppUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if s.updates == nil {
		writeError(w, http.StatusConflict, "application updates are unavailable")
		return
	}
	writeJSON(w, http.StatusOK, s.updates.AppUpdateStatus())
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
