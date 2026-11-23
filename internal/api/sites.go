package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// siteRow is one site as the Sites page sees it: its identity, the console it
// answers on, and the hostnames and settings that belong to it.
type siteRow struct {
	Slug          string    `json:"slug"`
	Name          string    `json:"name"`
	ConsoleHost   string    `json:"console_host"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
	Current       bool      `json:"current"`
	Hostnames     []string  `json:"hostnames"`
	RetentionDays string    `json:"retention_days"`
	Admins        int       `json:"admins"`
}

// rowFor reads one site's own rows. A site with no hostnames yet reports an
// empty list rather than null, so the console can render it without a guard.
func (s *Server) rowFor(current int64, site model.Site) siteRow {
	scoped := s.st.InSite(site.ID)
	row := siteRow{
		Slug: site.Slug, Name: site.Name, ConsoleHost: site.ConsoleHost,
		Enabled: site.Enabled, CreatedAt: site.CreatedAt,
		Current: site.ID == current, Hostnames: []string{},
	}
	if proxies, err := scoped.ListProxies(); err == nil {
		for _, p := range proxies {
			row.Hostnames = append(row.Hostnames, p.Hostname)
		}
	}
	if kv, err := scoped.Settings(); err == nil {
		row.RetentionDays = kv["retention_days"]
	}
	if users, err := scoped.ListUsers(); err == nil {
		row.Admins = len(users)
	}
	return row
}

// listSites returns every site with the rows it owns. It is the one endpoint
// that reads across sites, so it is gated on the sites area.
func (s *Server) listSites(w http.ResponseWriter, r *http.Request) {
	sites, err := s.st.ListSites()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	current := s.db(r).SiteID()
	out := make([]siteRow, 0, len(sites))
	for _, site := range sites {
		out = append(out, s.rowFor(current, site))
	}
	writeJSON(w, http.StatusOK, out)
}

type siteRequest struct {
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	ConsoleHost string `json:"console_host"`
	Enabled     *bool  `json:"enabled"`
}

// siteError turns a store failure into the status the console can act on.
func siteError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrDuplicate):
		writeError(w, http.StatusConflict, "a site with that slug or console host already exists")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "site not found")
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}

func (s *Server) createSite(w http.ResponseWriter, r *http.Request) {
	var in siteRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	site, err := s.st.CreateSite(in.Slug, in.Name, in.ConsoleHost)
	if err != nil {
		siteError(w, err)
		return
	}
	if in.Enabled != nil && !*in.Enabled {
		if site, err = s.st.UpdateSite(site.ID, site.Name, site.ConsoleHost, false); err != nil {
			siteError(w, err)
			return
		}
	}
	s.st.AddAudit(sessionFrom(r).Username, "site.create", site.Slug, clientIP(r))
	writeJSON(w, http.StatusCreated, s.rowFor(s.db(r).SiteID(), *site))
}

func (s *Server) updateSite(w http.ResponseWriter, r *http.Request) {
	site, err := s.st.SiteBySlug(r.PathValue("slug"))
	if err != nil {
		siteError(w, err)
		return
	}
	var in siteRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	name, host, enabled := site.Name, site.ConsoleHost, site.Enabled
	if in.Name != "" {
		name = in.Name
	}
	if in.ConsoleHost != "" {
		host = in.ConsoleHost
	}
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	if site.Slug == store.DefaultSiteSlug && !enabled {
		writeError(w, http.StatusConflict, "the default site serves the console this request came from and cannot be disabled")
		return
	}
	updated, err := s.st.UpdateSite(site.ID, name, host, enabled)
	if err != nil {
		siteError(w, err)
		return
	}
	s.st.AddAudit(sessionFrom(r).Username, "site.update", updated.Slug, clientIP(r))
	writeJSON(w, http.StatusOK, s.rowFor(s.db(r).SiteID(), *updated))
}

// deleteSite removes a site and every row it owns. The site serving the
// request is refused, because the reply would otherwise land on a console
// whose session no longer exists.
func (s *Server) deleteSite(w http.ResponseWriter, r *http.Request) {
	site, err := s.st.SiteBySlug(r.PathValue("slug"))
	if err != nil {
		siteError(w, err)
		return
	}
	if site.ID == s.db(r).SiteID() {
		writeError(w, http.StatusConflict, "this is the site whose console you are signed in on; switch sites first")
		return
	}
	if err := s.st.DeleteSite(site.ID); err != nil {
		siteError(w, err)
		return
	}
	// The site's instances read rows that no longer exist; forget them so the
	// next request through here rebuilds from scratch.
	if s.res != nil {
		s.res.Drop(site.ID)
	}
	s.st.AddAudit(sessionFrom(r).Username, "site.delete", site.Slug, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"removed": site.Slug})
}

// switchable lists the sites a console may switch to: every enabled site.
func (s *Server) switchable() []map[string]string {
	sites, err := s.st.ListSites()
	if err != nil {
		return nil
	}
	out := make([]map[string]string, 0, len(sites))
	for _, site := range sites {
		if !site.Enabled {
			continue
		}
		out = append(out, map[string]string{"slug": site.Slug, "name": site.Name, "console_host": site.ConsoleHost})
	}
	return out
}
