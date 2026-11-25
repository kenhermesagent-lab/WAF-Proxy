package api

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type traefikRouter struct {
	Name        string   `json:"name" yaml:"-"`
	Rule        string   `json:"rule" yaml:"rule"`
	Service     string   `json:"service" yaml:"service"`
	TLS         any      `json:"tls" yaml:"tls"`
	Status      string   `json:"status" yaml:"status"`
	Middlewares []string `json:"middlewares" yaml:"middlewares"`
}

type traefikService struct {
	Name         string `json:"name" yaml:"-"`
	LoadBalancer *struct {
		Servers []struct {
			URL string `json:"url" yaml:"url"`
		} `json:"servers" yaml:"servers"`
	} `json:"loadBalancer" yaml:"loadBalancer"`
}

type traefikFile struct {
	HTTP struct {
		Routers  map[string]traefikRouter  `yaml:"routers"`
		Services map[string]traefikService `yaml:"services"`
	} `yaml:"http"`
	TLS struct {
		Certificates []struct {
			CertFile string `yaml:"certFile"`
			KeyFile  string `yaml:"keyFile"`
		} `yaml:"certificates"`
	} `yaml:"tls"`
}

var traefikHostRule = regexp.MustCompile(`(?i)Host\(\s*([^)]*)\)`)

func parseTraefik(data []byte) (*migrationPreview, error) {
	files, err := migrationFiles(data)
	if err != nil {
		return nil, err
	}
	return parseTraefikFiles(files)
}

func parseTraefikFiles(files map[string][]byte) (*migrationPreview, error) {
	var lastErr error
	for _, data := range migrationConfigBodies(files, []string{"traefik.yml", "traefik.yaml", "traefik.json"}, ".yml", ".yaml", ".json") {
		var cfg traefikFile
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			lastErr = fmt.Errorf("the file is not Traefik YAML or JSON: %w", err)
			continue
		}
		if len(cfg.HTTP.Routers) == 0 {
			lastErr = fmt.Errorf("no http.routers found in the Traefik config")
			continue
		}
		var routers []traefikRouter
		for name, r := range cfg.HTTP.Routers {
			r.Name = name
			routers = append(routers, r)
		}
		var services []traefikService
		for name, svc := range cfg.HTTP.Services {
			svc.Name = name
			services = append(services, svc)
		}
		p := traefikPreview(routers, services)
		attachTraefikCerts(p, cfg, files)
		return p, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no Traefik YAML or JSON config was found in the upload")
	}
	return nil, lastErr
}

func attachTraefikCerts(p *migrationPreview, cfg traefikFile, files map[string][]byte) {
	for _, c := range cfg.TLS.Certificates {
		if !migrationRegisterCertFile(p, files, c.CertFile, c.KeyFile) {
			continue
		}
		certPEM := migrationFindFile(files, c.CertFile)
		for i := range p.Hosts {
			if p.Hosts[i].TLS && p.Hosts[i].CertRef == "" && certificateCoversHost(certPEM, p.Hosts[i].Hostname) {
				p.Hosts[i].CertRef = c.CertFile
				p.Hosts[i].CertKeyRef = c.KeyFile
				p.Hosts[i].CertName = c.CertFile
				migrationAddCertHost(p, c.CertFile, p.Hosts[i].Hostname)
			}
		}
	}
}

func (s *Server) fetchTraefik(r *http.Request, in migrationRequest) (*migrationPreview, error) {
	base, err := checkMigrationURL(in.URL)
	if err != nil {
		return nil, err
	}
	client := migrationHTTPClient(in.Insecure)
	var routers []traefikRouter
	var services []traefikService
	if err := migrationJSON(r.Context(), client, http.MethodGet, base+"/api/http/routers", "", nil, &routers); err != nil {
		return nil, fmt.Errorf("read Traefik routers: %w", err)
	}
	if err := migrationJSON(r.Context(), client, http.MethodGet, base+"/api/http/services", "", nil, &services); err != nil {
		return nil, fmt.Errorf("read Traefik services: %w", err)
	}
	return traefikPreview(routers, services), nil
}

func traefikPreview(routers []traefikRouter, services []traefikService) *migrationPreview {
	p := &migrationPreview{Source: "traefik"}
	byName := map[string]traefikService{}
	for _, svc := range services {
		byName[svc.Name] = svc
	}
	for _, router := range routers {
		hosts := traefikRuleHosts(router.Rule)
		if len(hosts) == 0 {
			p.Skipped = append(p.Skipped, router.Name+": no Host rule")
			continue
		}
		var ups []string
		if svc, ok := byName[router.Service]; ok && svc.LoadBalancer != nil {
			for _, server := range svc.LoadBalancer.Servers {
				if u := strings.TrimSpace(server.URL); u != "" {
					ups = append(ups, u)
				}
			}
		}
		enabled := !strings.EqualFold(router.Status, "disabled")
		tls := router.TLS != nil
		if v, ok := router.TLS.(bool); ok {
			tls = v
		}
		for _, host := range hosts {
			p.addHost(migrationHost{
				Hostname: host, Upstreams: ups, Enabled: enabled,
				TLS: tls,
			})
		}
		if strings.Contains(strings.ToLower(router.Rule), "path") {
			p.Notes = appendUnique(p.Notes, "Traefik path rules are not imported; each hostname points at its service's servers.")
		}
		if len(router.Middlewares) > 0 {
			p.Notes = appendUnique(p.Notes, "Traefik middlewares (redirects, headers, auth) are not imported.")
		}
	}
	if len(p.Hosts) == 0 && len(p.Skipped) == 0 {
		return &migrationPreview{Source: "traefik", Notes: []string{"No HTTP routers with Host rules were found."}}
	}
	return p
}

func traefikRuleHosts(rule string) []string {
	var hosts []string
	for _, match := range traefikHostRule.FindAllStringSubmatch(rule, -1) {
		for _, raw := range strings.Split(match[1], ",") {
			host := strings.ToLower(strings.Trim(strings.TrimSpace(raw), "`\"'"))
			if host != "" {
				hosts = append(hosts, host)
			}
		}
	}
	return hosts
}
