package api

import (
	"net/http"
)

func (s *Server) getGeoIP(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.geo.Status())
}

// installGeoIP starts the download and returns immediately: the city database
// is large, so the Settings page polls the status instead of holding a request
// open for the whole download.
func (s *Server) installGeoIP(w http.ResponseWriter, r *http.Request) {
	if !s.geo.StartInstall() {
		writeError(w, http.StatusConflict, "a GeoIP install is already running")
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "geoip.install", "DB-IP Lite city and ASN", clientIP(r))
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "installing"})
}
