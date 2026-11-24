package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	settingCrowdSecEnabled = "crowdsec_enabled"
	settingCrowdSecURL     = "crowdsec_url"
	settingCrowdSecKey     = "crowdsec_key"
)

type crowdsecBody struct {
	Enabled  bool   `json:"enabled"`
	URL      string `json:"url"`
	Key      string `json:"key"`
	ClearKey bool   `json:"clear_key"`
}

// storedCrowdSec returns the console-managed bouncer configuration, falling
// back to the environment values installed before the console page existed.
func (s *Server) storedCrowdSec() (enabled bool, lapi, key string) {
	kv, err := s.st.Settings()
	if err == nil {
		if raw, ok := kv[settingCrowdSecEnabled]; ok {
			enabled = raw == "1"
		}
		lapi = strings.TrimSpace(kv[settingCrowdSecURL])
		if enc := kv[settingCrowdSecKey]; enc != "" {
			if plain, err := s.box.Open(enc); err == nil {
				key = plain
			}
		}
	}
	if lapi == "" {
		lapi = strings.TrimSpace(s.cfg.CrowdSecURL)
	}
	if key == "" {
		key = strings.TrimSpace(s.cfg.CrowdSecKey)
	}
	if _, ok := kv[settingCrowdSecEnabled]; !ok {
		enabled = strings.TrimSpace(s.cfg.CrowdSecURL) != "" && strings.TrimSpace(s.cfg.CrowdSecKey) != ""
	}
	return enabled, lapi, key
}

func (s *Server) getCrowdSec(w http.ResponseWriter, r *http.Request) {
	if !s.requireHostConsole(w, r, "CrowdSec") {
		return
	}
	enabled, lapi, key := s.storedCrowdSec()
	status := s.cs.Status()
	status["config"] = map[string]any{
		"enabled": enabled, "url": lapi, "key_set": key != "",
		"attribution": "CrowdSec Security Engine / LAPI",
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) putCrowdSec(w http.ResponseWriter, r *http.Request) {
	if !s.requireHostConsole(w, r, "CrowdSec") {
		return
	}
	var in crowdsecBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	_, oldURL, oldKey := s.storedCrowdSec()
	lapi := strings.TrimSpace(in.URL)
	if lapi == "" {
		lapi = oldURL
	}
	lapi = strings.TrimRight(lapi, "/")
	if lapi != "" {
		parsed, err := url.Parse(lapi)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
			writeError(w, http.StatusBadRequest, "LAPI URL must be an http(s) URL without embedded credentials")
			return
		}
	}
	key := strings.TrimSpace(in.Key)
	if key == "" && !in.ClearKey {
		key = oldKey
	}
	if in.ClearKey {
		key = ""
	}
	if len(key) > 4096 {
		writeError(w, http.StatusBadRequest, "bouncer key is too long")
		return
	}
	if in.Enabled && (lapi == "" || key == "") {
		writeError(w, http.StatusBadRequest, "an enabled bouncer needs both a LAPI URL and a bouncer key")
		return
	}

	if err := s.saveCrowdSecConfig(in.Enabled, lapi, key); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "crowdsec.configure", lapi, clientIP(r))
	s.getCrowdSec(w, r)
}

// saveCrowdSecConfig stores the bouncer endpoint and key and applies them to the
// running manager. The key is sealed with the installation master key; an empty
// endpoint or key disables polling.
func (s *Server) saveCrowdSecConfig(enabled bool, lapi, key string) error {
	lapi = strings.TrimRight(strings.TrimSpace(lapi), "/")
	settings := map[string]string{settingCrowdSecEnabled: "0", settingCrowdSecURL: lapi}
	if enabled && lapi != "" && key != "" {
		settings[settingCrowdSecEnabled] = "1"
	}
	if key == "" {
		settings[settingCrowdSecKey] = ""
	} else {
		enc, err := s.box.Seal(key)
		if err != nil {
			return errors.New("encryption error")
		}
		settings[settingCrowdSecKey] = enc
	}
	if err := s.st.SetSettings(settings); err != nil {
		return errors.New("cannot save CrowdSec settings")
	}
	if settings[settingCrowdSecEnabled] == "1" {
		s.cs.SetConfig(lapi, key)
	} else {
		s.cs.SetConfig("", "")
	}
	return nil
}

func (s *Server) testCrowdSec(w http.ResponseWriter, r *http.Request) {
	if !s.requireHostConsole(w, r, "CrowdSec") {
		return
	}
	var in crowdsecBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	_, lapi, key := s.storedCrowdSec()
	if strings.TrimSpace(in.URL) != "" {
		lapi = strings.TrimRight(strings.TrimSpace(in.URL), "/")
	}
	if strings.TrimSpace(in.Key) != "" {
		key = strings.TrimSpace(in.Key)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := s.cs.Probe(ctx, lapi, key); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
