package api

import (
	"net/http"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// securitySourceSpec is each external vulnerability source with the cadence it
// is meant to sync at. Three times the cadence is stale, and everything that
// depends on a stale source is reported unknown rather than clean.
var securitySourceSpec = []struct {
	name    string
	cadence time.Duration
}{
	{"kev", 24 * time.Hour},
	{"osv", 7 * 24 * time.Hour},
}

// securityStorageCap is the storage budget docs/SECURITY-SCAN.md §5 sets for
// the whole feature.
const securityStorageCap = 30 << 20

type securityFeedSource struct {
	Source     string `json:"source"`
	LastOK     string `json:"last_ok,omitempty"`
	LastError  string `json:"last_error,omitempty"`
	AgeSeconds int64  `json:"age_seconds,omitempty"`
	Stale      bool   `json:"stale"`
	Bytes      int64  `json:"bytes"`
	Records    int    `json:"records"`
	SHA256     string `json:"sha256,omitempty"`
}

// getSecurityFeed reports what the node knows about its vulnerability sources:
// when each last synced, how large it is and whether it is stale. A source that
// has never synced is stale, never current.
func (s *Server) getSecurityFeed(w http.ResponseWriter, r *http.Request) {
	sources, err := securityFeedSources(s.db(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sources":           sources,
		"storage_cap_bytes": securityStorageCap,
	})
}

// securityFeedSources reports each known source, including one that has never
// synced, which is stale rather than current.
func securityFeedSources(st *store.Store) ([]securityFeedSource, error) {
	known, err := st.VulnSources()
	if err != nil {
		return nil, err
	}
	byName := make(map[string]store.VulnSource, len(known))
	for _, src := range known {
		byName[src.Source] = src
	}
	now := time.Now()
	out := make([]securityFeedSource, 0, len(securitySourceSpec))
	for _, spec := range securitySourceSpec {
		src := byName[spec.name]
		row := securityFeedSource{
			Source: spec.name, LastError: src.LastError, Bytes: src.Bytes,
			Records: src.Records, SHA256: src.SHA256, Stale: true,
		}
		if !src.LastOK.IsZero() {
			row.LastOK = src.LastOK.UTC().Format(time.RFC3339)
			row.AgeSeconds = int64(now.Sub(src.LastOK).Seconds())
			row.Stale = now.Sub(src.LastOK) > 3*spec.cadence
		}
		out = append(out, row)
	}
	return out, nil
}
