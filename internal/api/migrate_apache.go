package api

import (
	"fmt"
	"path"
	"strings"
)

type apacheVhost struct {
	hosts    []string
	tls      bool
	proxy    string
	proxyN   int
	redirect string
	status   int
	cert     string
	key      string
}

func parseApache(files map[string][]byte) (*migrationPreview, error) {
	p := &migrationPreview{Source: "apache"}
	var vhosts []apacheVhost
	parsed := 0
	for name, body := range files {
		if !migrationFileMatch(name, ".conf", ".vhost", ".txt") && name != "config" {
			continue
		}
		parsed++
		vhosts = append(vhosts, apacheParse(migrationText(body))...)
	}
	if parsed == 0 {
		return nil, fmt.Errorf("no Apache .conf files found in the upload")
	}
	for _, vh := range vhosts {
		if vh.proxyN > 0 {
			p.Notes = appendUnique(p.Notes, "Apache vhosts with path-specific ProxyPass targets are flattened onto one upstream per hostname.")
		}
		for _, host := range vh.hosts {
			h := migrationHost{Hostname: host, Enabled: true, TLS: vh.tls}
			if vh.proxy != "" {
				h.Upstreams = []string{vh.proxy}
			}
			if vh.cert != "" && vh.key != "" {
				h.CertRef, h.CertKeyRef = vh.cert, vh.key
				h.CertName = path.Base(vh.cert)
				addApacheCert(p, files, vh, host)
			}
			p.addHost(h)
			if vh.proxy == "" && vh.redirect != "" {
				p.addRedirect(migrationRedirect{Hostname: host, Target: vh.redirect, Status: apacheStatus(vh.status), Enabled: true})
			}
		}
	}
	if len(p.Hosts) == 0 && len(p.Redirects) == 0 {
		return nil, fmt.Errorf("no Apache VirtualHost with ServerName and ProxyPass or Redirect was found")
	}
	return p, nil
}

func apacheParse(text string) []apacheVhost {
	var out []apacheVhost
	var current *apacheVhost
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(stripHashComment(raw))
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "<virtualhost") {
			current = &apacheVhost{tls: strings.Contains(lower, ":443")}
			continue
		}
		if strings.HasPrefix(lower, "</virtualhost>") {
			if current != nil && len(current.hosts) > 0 {
				out = append(out, *current)
			}
			current = nil
			continue
		}
		if current == nil {
			continue
		}
		fields := apacheFields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "servername":
			if len(fields) > 1 {
				current.hosts = appendUnique(current.hosts, trimApacheHost(fields[1]))
			}
		case "serveralias":
			for _, rawHost := range fields[1:] {
				current.hosts = appendUnique(current.hosts, trimApacheHost(rawHost))
			}
		case "proxypass":
			if len(fields) > 2 && strings.HasPrefix(fields[1], "/") {
				if current.proxy != "" && current.proxy != trimApache(fields[2]) {
					current.proxyN++
				}
				current.proxy = trimApache(fields[2])
			}
		case "redirect":
			if len(fields) > 2 {
				switch strings.ToLower(fields[1]) {
				case "permanent", "301":
					current.status = 301
				case "temp", "temporary", "302":
					current.status = 302
				}
				current.redirect = trimApache(fields[len(fields)-1])
			}
		case "sslengine":
			if len(fields) > 1 && strings.EqualFold(fields[1], "on") {
				current.tls = true
			}
		case "sslcertificatefile":
			if len(fields) > 1 {
				current.cert = trimApache(fields[1])
			}
		case "sslcertificatekeyfile":
			if len(fields) > 1 {
				current.key = trimApache(fields[1])
			}
		case "rewriterule", "proxypassmatch":
			continue
		}
	}
	return out
}

func apacheFields(line string) []string {
	var fields []string
	var word strings.Builder
	var quote rune
	for _, r := range line {
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				word.WriteRune(r)
			}
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
		case ' ', '\t':
			if word.Len() > 0 {
				fields = append(fields, word.String())
				word.Reset()
			}
		default:
			word.WriteRune(r)
		}
	}
	if word.Len() > 0 {
		fields = append(fields, word.String())
	}
	return fields
}

func trimApache(s string) string {
	return strings.Trim(strings.TrimSpace(s), `"'`)
}

func trimApacheHost(raw string) string {
	host := strings.ToLower(trimApache(raw))
	if i := strings.IndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	if host == "" || strings.HasPrefix(host, "_") || strings.Contains(host, "*") {
		return ""
	}
	return host
}

func apacheStatus(code int) int {
	switch code {
	case 301, 302, 307, 308:
		return code
	}
	return 302
}

func addApacheCert(p *migrationPreview, files map[string][]byte, vh apacheVhost, host string) {
	for i := range p.Certificates {
		if p.Certificates[i].Ref != vh.cert {
			continue
		}
		if !containsString(p.Certificates[i].Hosts, host) {
			p.Certificates[i].Hosts = append(p.Certificates[i].Hosts, host)
		}
		return
	}
	row := migrationCertificate{Ref: vh.cert, Domains: strings.Join(vh.hosts, ", "), Provider: "upload", Hosts: []string{host}}
	if migrationFindFile(files, vh.cert) != nil && migrationFindFile(files, vh.key) != nil {
		row.Importable = true
	} else {
		row.Problem = "the certificate and key files are not in the upload"
	}
	p.Certificates = append(p.Certificates, row)
}
