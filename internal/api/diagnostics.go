package api

import (
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/canary"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/version"
)

// sensitiveKey marks a setting whose value must never leave the host, even when
// the console's own view of it is masked.
var sensitiveKey = regexp.MustCompile(`(?i)(token|secret|password|passwd|_key$|hash|credential|webhook|_url$)`)

func sensitiveSetting(key string) bool {
	return sensitiveKey.MatchString(strings.ToLower(key))
}

// redactValue keeps a URL useful for diagnosis while dropping credentials and
// query strings, which is where tokens tend to hide.
func redactValue(v string) string {
	if !strings.Contains(v, "://") {
		return v
	}
	u, err := url.Parse(v)
	if err != nil {
		return "[redacted]"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func redactSettings(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if sensitiveSetting(k) {
			if v == "" {
				out[k] = ""
			} else {
				out[k] = "[redacted]"
			}
			continue
		}
		out[k] = redactValue(v)
	}
	return out
}

// diagnostics returns a support bundle an operator can paste into a ticket:
// versions, listener addresses, redacted settings, configuration counts and
// certificate metadata. No secrets, keys or administrator hashes are included.
func (s *Server) diagnostics(w http.ResponseWriter, r *http.Request) {
	settings, _ := s.db(r).Settings()
	proxies, _ := s.db(r).ListProxies()
	bans, _ := s.db(r).ListBans(true)
	policies, _ := s.db(r).ListPolicies()
	certs, _ := s.db(r).ListCerts()
	feeds, _ := s.db(r).ListFeeds()

	certRows := make([]map[string]any, 0, len(certs))
	for _, c := range certs {
		expires := ""
		if c.ExpiresAt != nil {
			expires = c.ExpiresAt.UTC().Format(time.RFC3339)
		}
		certRows = append(certRows, map[string]any{
			"domains": c.Domains, "status": c.Status, "source": c.Source,
			"expires_at": expires, "last_error": c.LastError,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"version":      version.Version,
		"go_version":   runtime.Version(),
		"platform":     runtime.GOOS + "/" + runtime.GOARCH,
		"listen": map[string]string{
			"wan": s.cfg.ListenWAN, "gui": s.cfg.ListenGUI, "http": s.cfg.ListenHTTP,
		},
		"settings":  redactSettings(settings),
		"proxies":   len(proxies),
		"certs":     certRows,
		"bans":      len(bans),
		"policies":  len(policies),
		"feeds":     len(feeds),
		"redaction": "values of secret keys, URL credentials and URL queries are removed",
	})
}

// runCanary probes one site end to end. The body may name a site by id or a
// hostname directly; with neither, the first configured site is used.
func (s *Server) runCanary(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ProxyID int64  `json:"proxy_id"`
		Host    string `json:"host"`
	}
	if r.ContentLength > 0 {
		if err := decode(r, &in); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
	}
	host := strings.TrimSpace(in.Host)
	if host == "" && in.ProxyID != 0 {
		p, err := s.db(r).GetProxy(in.ProxyID)
		if err != nil || p == nil {
			writeError(w, http.StatusNotFound, "site not found")
			return
		}
		host = p.Hostname
	}
	if host == "" {
		if list, _ := s.db(r).ListProxies(); len(list) > 0 {
			host = list[0].Hostname
		}
	}
	if host == "" {
		writeError(w, http.StatusBadRequest, "no site to probe")
		return
	}
	res := (canary.Prober{}).Run(r.Context(), host)
	code := http.StatusOK
	if !res.OK {
		code = http.StatusBadGateway
	}
	writeJSON(w, code, res)
}
