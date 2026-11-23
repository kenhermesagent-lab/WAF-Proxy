package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/rbac"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// searchResult is one entry in the console command palette. Results are
// filtered by the caller's own permissions: a role that cannot read bans must
// not learn a banned address exists by searching for it.
type searchResult struct {
	Kind     string `json:"kind"`
	Title    string `json:"title"`
	Subtitle string `json:"subtitle"`
	Href     string `json:"href"`
}

func (s *Server) globalSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	out := []searchResult{}
	if len(q) < 2 {
		writeJSON(w, http.StatusOK, map[string]any{"results": out})
		return
	}
	sess := sessionFrom(r)
	lower := strings.ToLower(q)

	if sess.Can(rbac.Permission("proxies", "read")) {
		if list, err := s.db(r).ListProxies(); err == nil {
			for _, p := range list {
				if !strings.Contains(strings.ToLower(p.Hostname), lower) {
					continue
				}
				state := "disabled"
				if p.Enabled {
					state = "enabled"
				}
				out = append(out, searchResult{
					Kind: "proxy", Title: p.Hostname,
					Subtitle: "Proxy · " + state, Href: "#/proxies",
				})
			}
		}
	}

	if sess.Can(rbac.Permission("traffic", "read")) {
		if ips, err := s.db(r).IPSummaries(store.EventFilter{}, q, 5); err == nil {
			for _, ip := range ips {
				sub := "Source IP"
				if ip.Country != "" {
					sub += " · " + ip.Country
				}
				if ip.Blocked > 0 {
					sub += " · " + strconv.FormatInt(ip.Blocked, 10) + " blocked"
				}
				out = append(out, searchResult{
					Kind: "ip", Title: ip.IP, Subtitle: sub, Href: "#/logs?ip=" + ip.IP,
				})
			}
		}
	}

	if sess.Can(rbac.Permission("traffic", "read")) {
		if events, _, err := s.db(r).QueryEvents(store.EventFilter{Limit: 200}); err == nil {
			added := 0
			for _, e := range events {
				if !strings.Contains(strings.ToLower(e.Host+" "+e.Path+" "+e.RuleMsg+" "+e.Stage), lower) {
					continue
				}
				sub := e.Host + " · " + e.SrcIP
				if e.Stage != "" {
					sub += " · " + e.Stage
				}
				out = append(out, searchResult{
					Kind: "event", Title: e.Method + " " + e.Path,
					Subtitle: sub, Href: "#/logs?ip=" + e.SrcIP,
				})
				added++
				if added >= 5 {
					break
				}
			}
		}
	}

	if sess.Can(rbac.Permission("policies", "read")) {
		if bans, err := s.db(r).ListBans(true); err == nil {
			for _, b := range bans {
				if !strings.Contains(strings.ToLower(b.CIDR), lower) {
					continue
				}
				out = append(out, searchResult{
					Kind: "ban", Title: b.CIDR, Subtitle: "Ban · " + b.Reason, Href: "#/policies",
				})
			}
		}
	}

	if len(out) > 20 {
		out = out[:20]
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": out})
}
