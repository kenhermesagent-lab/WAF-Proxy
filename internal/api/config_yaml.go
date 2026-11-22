package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"gopkg.in/yaml.v3"
)

// exportConfigYAML renders the configuration the JSON backup already exports as
// readable YAML. Secrets stay excluded there, so nothing new can leak here.
func (s *Server) exportConfigYAML(w http.ResponseWriter, _ *http.Request) {
	data, err := s.backupDocument()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot build the configuration")
		return
	}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot convert the configuration")
		return
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot convert the configuration")
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="wafproxy.yaml"`)
	_, _ = w.Write(out)
}

// importConfigYAML accepts the exported document and hands it to the backup
// import, so validation, skipping and the reload stay in one place.
func (s *Server) importConfigYAML(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid configuration file")
		return
	}
	var doc any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		writeError(w, http.StatusBadRequest, "invalid configuration file")
		return
	}
	// Readable YAML invites unquoted numbers and booleans; the backup format
	// stores settings and the version as strings.
	if top, ok := doc.(map[string]any); ok {
		for _, key := range []string{"version", "note"} {
			if v, ok := top[key]; ok {
				top[key] = fmt.Sprint(v)
			}
		}
		if settings, ok := top["settings"].(map[string]any); ok {
			for key, v := range settings {
				settings[key] = fmt.Sprint(v)
			}
		}
	}
	js, err := json.Marshal(doc)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid configuration file")
		return
	}
	s.applyBackup(w, r, js, "config.import")
}
