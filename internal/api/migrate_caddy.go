package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type caddyConfig struct {
	Apps struct {
		HTTP struct {
			Servers map[string]caddyServer `json:"servers"`
		} `json:"http"`
		TLS struct {
			Certificates struct {
				LoadFiles []struct {
					Certificate string `json:"certificate"`
					Key         string `json:"key"`
				} `json:"load_files"`
			} `json:"certificates"`
		} `json:"tls"`
	} `json:"apps"`
}

type caddyServer struct {
	Listen []string     `json:"listen"`
	Routes []caddyRoute `json:"routes"`
}

type caddyRoute struct {
	Match  []caddyMatch   `json:"match"`
	Handle []caddyHandler `json:"handle"`
}

type caddyMatch struct {
	Host []string `json:"host"`
}

type caddyHandler struct {
	Handler    string          `json:"handler"`
	Upstreams  []caddyUpstream `json:"upstreams"`
	Routes     []caddyRoute    `json:"routes"`
	StatusCode int             `json:"status_code"`
	Headers    map[string]any  `json:"headers"`
}

type caddyUpstream struct {
	Dial string `json:"dial"`
}

func (s *Server) fetchCaddy(r *http.Request, in migrationRequest) (*migrationPreview, error) {
	base, err := checkMigrationURL(in.URL)
	if err != nil {
		return nil, err
	}
	client := migrationHTTPClient(in.Insecure)
	var cfg caddyConfig
	if err := migrationJSON(r.Context(), client, http.MethodGet, base+"/config/", "", nil, &cfg); err != nil {
		return nil, fmt.Errorf("read Caddy config: %w", err)
	}
	if len(cfg.Apps.HTTP.Servers) == 0 {
		return nil, fmt.Errorf("Caddy returned no HTTP servers")
	}
	return caddyPreview(cfg), nil
}

func parseCaddy(data []byte) (*migrationPreview, error) {
	files, err := migrationFiles(data)
	if err != nil {
		return nil, err
	}
	return parseCaddyFiles(files)
}

func parseCaddyFiles(files map[string][]byte) (*migrationPreview, error) {
	var lastErr error
	for _, data := range migrationConfigBodies(files, []string{"Caddyfile"}, ".caddyfile", ".json", ".txt") {
		trimmed := strings.TrimSpace(migrationText(data))
		if strings.HasPrefix(trimmed, "{") {
			var cfg caddyConfig
			if err := json.Unmarshal([]byte(trimmed), &cfg); err == nil && len(cfg.Apps.HTTP.Servers) > 0 {
				p := caddyPreview(cfg)
				attachCaddyJSONCerts(p, cfg, files)
				return p, nil
			}
		}
		p, err := parseCaddyfile(trimmed, files)
		if err == nil {
			return p, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no Caddyfile or Caddy JSON config was found in the upload")
	}
	return nil, lastErr
}

func attachCaddyJSONCerts(p *migrationPreview, cfg caddyConfig, files map[string][]byte) {
	for _, lf := range cfg.Apps.TLS.Certificates.LoadFiles {
		if !migrationRegisterCertFile(p, files, lf.Certificate, lf.Key) {
			continue
		}
		certPEM := migrationFindFile(files, lf.Certificate)
		for i := range p.Hosts {
			if p.Hosts[i].TLS && p.Hosts[i].CertRef == "" && certificateCoversHost(certPEM, p.Hosts[i].Hostname) {
				p.Hosts[i].CertRef = lf.Certificate
				p.Hosts[i].CertKeyRef = lf.Key
				p.Hosts[i].CertName = lf.Certificate
				migrationAddCertHost(p, lf.Certificate, p.Hosts[i].Hostname)
			}
		}
	}
}

func caddyPreview(cfg caddyConfig) *migrationPreview {
	p := &migrationPreview{Source: "caddy"}
	for _, server := range cfg.Apps.HTTP.Servers {
		tls := true
		for _, listen := range server.Listen {
			if strings.HasSuffix(listen, ":80") {
				tls = false
			}
		}
		walkCaddyRoutes(p, server.Routes, nil, tls)
	}
	if len(p.Hosts) == 0 && len(p.Redirects) == 0 {
		p.Notes = appendUnique(p.Notes, "No Caddy routes with host matchers and reverse_proxy handlers were found.")
	}
	return p
}

func walkCaddyRoutes(p *migrationPreview, routes []caddyRoute, inherited []string, tls bool) {
	for _, route := range routes {
		hosts := inherited
		if len(route.Match) > 0 && len(route.Match[0].Host) > 0 {
			hosts = route.Match[0].Host
		}
		for _, handle := range route.Handle {
			switch handle.Handler {
			case "reverse_proxy":
				var ups []string
				for _, upstream := range handle.Upstreams {
					if up := caddyDialURL(upstream.Dial); up != "" {
						ups = append(ups, up)
					}
				}
				for _, host := range hosts {
					p.addHost(migrationHost{Hostname: host, Upstreams: ups, Enabled: true, TLS: tls})
				}
			case "static_response":
				location := caddyHeader(handle.Headers, "Location")
				if location != "" && len(hosts) > 0 {
					status := handle.StatusCode
					if status < 300 || status > 399 {
						status = 302
					}
					for _, host := range hosts {
						p.addRedirect(migrationRedirect{Hostname: host, Target: location, Status: status, Enabled: true})
					}
				}
			case "subroute":
				walkCaddyRoutes(p, handle.Routes, hosts, tls)
			}
		}
	}
}

func caddyDialURL(dial string) string {
	dial = strings.TrimSpace(dial)
	if dial == "" || strings.HasPrefix(dial, "unix/") {
		return ""
	}
	if strings.Contains(dial, "://") {
		return dial
	}
	return "http://" + dial
}

func caddyHeader(headers map[string]any, name string) string {
	for key, value := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		switch v := value.(type) {
		case string:
			return v
		case []any:
			if len(v) > 0 {
				if s, ok := v[0].(string); ok {
					return s
				}
			}
		}
	}
	return ""
}

type caddySite struct {
	hosts       []string
	upstream    []string
	tls         bool
	cert        string
	key         string
	redirTarget string
	redirStatus int
}

func parseCaddyfile(text string, files map[string][]byte) (*migrationPreview, error) {
	p := &migrationPreview{Source: "caddy"}
	var site *caddySite
	depth, siteDepth := 0, -1
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(stripHashComment(raw))
		if line == "" {
			continue
		}
		if site == nil && depth == 0 && line != "{" && strings.HasSuffix(line, "{") {
			addresses := strings.TrimSpace(strings.TrimSuffix(line, "{"))
			if addresses != "" && !strings.HasPrefix(addresses, "(") {
				site = &caddySite{hosts: caddyAddresses(addresses), tls: true}
				siteDepth = depth + 1
			}
		} else if site != nil {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				switch fields[0] {
				case "reverse_proxy":
					for _, arg := range fields[1:] {
						if arg == "{" || strings.HasPrefix(arg, "/") {
							if strings.HasPrefix(arg, "/") {
								p.Notes = appendUnique(p.Notes, "Caddy path-specific reverse_proxy handlers are flattened onto the whole hostname.")
							}
							continue
						}
						if up := caddyDialURL(strings.Trim(arg, `"`)); up != "" {
							site.upstream = appendUnique(site.upstream, up)
						}
					}
				case "redir":
					if len(fields) > 1 {
						site.redirTarget = fields[1]
						site.redirStatus = 302
						for _, arg := range fields[2:] {
							switch strings.ToLower(arg) {
							case "permanent", "301":
								site.redirStatus = 301
							case "temporary", "302":
								site.redirStatus = 302
							case "307":
								site.redirStatus = 307
							case "308":
								site.redirStatus = 308
							}
						}
					}
				case "tls":
					site.tls = true
					if len(fields) >= 3 && fields[1] != "internal" {
						site.cert = strings.Trim(fields[1], `"`)
						site.key = strings.Trim(fields[2], `"`)
					}
				case "handle", "handle_path", "route":
					if len(fields) > 1 && fields[1] != "{" {
						p.Notes = appendUnique(p.Notes, "Caddy path-specific handlers are flattened onto the whole hostname.")
					}
				case "import":
					p.Notes = appendUnique(p.Notes, "Caddy import directives are not followed; import the referenced files separately.")
				}
			}
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if site != nil && depth < siteDepth {
			flushCaddySite(p, site, files)
			site = nil
			siteDepth = -1
		}
	}
	if site != nil {
		flushCaddySite(p, site, files)
	}
	if len(p.Hosts) == 0 && len(p.Redirects) == 0 {
		return nil, fmt.Errorf("no Caddy site blocks with reverse_proxy or redir were found")
	}
	return p, nil
}

func flushCaddySite(p *migrationPreview, site *caddySite, files map[string][]byte) {
	certOK := site.cert != "" && migrationRegisterCertFile(p, files, site.cert, site.key)
	for _, host := range site.hosts {
		if len(site.upstream) > 0 {
			h := migrationHost{Hostname: host, Upstreams: site.upstream, Enabled: true, TLS: site.tls}
			if certOK {
				h.CertRef, h.CertKeyRef, h.CertName = site.cert, site.key, site.cert
				migrationAddCertHost(p, site.cert, host)
			}
			p.addHost(h)
			continue
		}
		target := caddyRedirectTarget(site.redirTarget, []string{host})
		if target != "" {
			p.addRedirect(migrationRedirect{Hostname: host, Target: target, Status: site.redirStatus, Enabled: true})
		}
	}
}

func caddyAddresses(raw string) []string {
	var hosts []string
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(strings.TrimPrefix(part, "https://"), "http://")
		if i := strings.IndexByte(part, '/'); i >= 0 {
			part = part[:i]
		}
		if strings.HasPrefix(part, ":") || part == "localhost" || strings.HasPrefix(part, "[") {
			continue
		}
		if i := strings.LastIndexByte(part, ':'); i > 0 && !strings.Contains(part[i+1:], ":") {
			part = part[:i]
		}
		if part != "" {
			hosts = appendUnique(hosts, strings.ToLower(part))
		}
	}
	return hosts
}

func caddyRedirectTarget(target string, hosts []string) string {
	target = strings.Trim(target, `"`)
	if strings.HasPrefix(target, "/") || len(hosts) == 0 {
		return ""
	}
	target = strings.ReplaceAll(target, "{host}", hosts[0])
	target = strings.ReplaceAll(target, "{uri}", "$path")
	target = strings.ReplaceAll(target, "{path}", "$path")
	return target
}

func stripHashComment(line string) string {
	inSingle, inDouble := false, false
	for i, r := range line {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return line[:i]
			}
		}
	}
	return line
}
