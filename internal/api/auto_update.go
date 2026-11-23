package api

import (
	"context"
	"net/http"
	"strings"
	"time"
)

type autoUpdateConfig struct {
	Enabled bool   `json:"enabled"`
	Time    string `json:"time"`
}

func (s *Server) autoUpdateSettings() autoUpdateConfig {
	kv, err := s.st.Settings()
	if err != nil {
		return autoUpdateConfig{Time: "04:00"}
	}
	cfg := autoUpdateConfig{Enabled: kv["auto_update_enabled"] == "1", Time: strings.TrimSpace(kv["auto_update_time"])}
	if cfg.Time == "" {
		cfg.Time = "04:00"
	}
	return cfg
}

func (s *Server) getAutoUpdate(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.autoUpdateSettings())
}

func (s *Server) putAutoUpdate(w http.ResponseWriter, r *http.Request) {
	var in autoUpdateConfig
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if in.Time == "" {
		in.Time = "04:00"
	}
	if _, err := time.Parse("15:04", in.Time); err != nil {
		writeError(w, http.StatusBadRequest, "the run time must be HH:MM")
		return
	}
	if err := s.db(r).SetSetting("auto_update_enabled", map[bool]string{true: "1", false: "0"}[in.Enabled]); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot save")
		return
	}
	if err := s.db(r).SetSetting("auto_update_time", in.Time); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot save")
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "updates.auto_configure", in.Time, clientIP(r))
	writeJSON(w, http.StatusOK, in)
}

// StartAutoUpdate applies a newer build once a day at the configured time. It
// is off by default: an unattended root rebuild is an operator decision.
func (s *Server) StartAutoUpdate(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		last := ""
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				cfg := s.autoUpdateSettings()
				if !cfg.Enabled {
					continue
				}
				hhmm, err := time.Parse("15:04", cfg.Time)
				if err != nil {
					continue
				}
				target := time.Date(now.Year(), now.Month(), now.Day(), hhmm.Hour(), hhmm.Minute(), 0, 0, now.Location())
				key := target.Format("20060102")
				if now.Before(target) || key == last {
					continue
				}
				last = key
				s.runAutoUpdate(ctx)
			}
		}
	}()
}

func (s *Server) runAutoUpdate(ctx context.Context) {
	if s.updates == nil {
		return
	}
	snap, err := s.updates.Check(ctx)
	if err != nil {
		s.notifyFor(nil).Enqueue("update", "Automatic update check failed: "+err.Error(), "auto-update-check", true)
		return
	}
	if !snap.AppUpdateAvailable {
		return
	}
	if !snap.AppUpdateSupported {
		s.notifyFor(nil).Enqueue("update", "A newer build is available but this host cannot apply it: "+snap.AppUpdateReason, "auto-update-unsupported", true)
		return
	}
	s.st.AddAudit("system", "updates.auto", snap.AppRemoteVersion, "scheduler")
	err = s.updates.StartAppUpdate(func() {
		s.notifyFor(nil).Enqueue("update", "Automatic update finished; the console is restarting on the new build.", "auto-update-done", true)
	})
	if err != nil {
		s.notifyFor(nil).Enqueue("update", "Automatic update could not start: "+err.Error(), "auto-update-start", true)
		return
	}
	s.notifyFor(nil).Enqueue("update", "Automatic update started for "+snap.AppRemoteVersion+".", "auto-update-start", true)
}
