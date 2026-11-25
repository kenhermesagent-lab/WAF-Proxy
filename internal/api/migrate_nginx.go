package api

import (
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
)

type nginxServer struct {
	hosts  []string
	tls    bool
	cert   string
	key    string
	proxy  string
	proxyN int
	ret    string
	status int
}

func parseNginx(files map[string][]byte) (*migrationPreview, error) {
	p := &migrationPreview{Source: "nginx"}
	upstreams := map[string][]string{}
	var servers []nginxServer
	parsed := 0
	for name, body := range files {
		if !migrationFileMatch(name, ".conf") && name != "config" {
			continue
		}
		parsed++
		us, ss, err := nginxParse(nginxTokens(migrationText(body)))
		if err != nil {
			p.Skipped = append(p.Skipped, name+": "+err.Error())
			continue
		}
		for k, v := range us {
			upstreams[k] = append(upstreams[k], v...)
		}
		servers = append(servers, ss...)
	}
	if parsed == 0 {
		return nil, fmt.Errorf("no .conf files found in the upload")
	}
	for _, srv := range servers {
		if len(srv.hosts) == 0 {
			continue
		}
		if srv.proxy == "" && srv.ret == "" {
			continue
		}
		if srv.proxyN > 0 {
			p.Notes = appendUnique(p.Notes, "Nginx locations with different proxy_pass targets are flattened onto one upstream per hostname.")
		}
		ups := nginxProxyURLs(srv.proxy, upstreams)
		for _, host := range srv.hosts {
			h := migrationHost{Hostname: host, Upstreams: ups, Enabled: true, TLS: srv.tls}
			if srv.cert != "" && srv.key != "" {
				h.CertRef, h.CertKeyRef = srv.cert, srv.key
				h.CertName = path.Base(srv.cert)
				addNginxCert(p, files, srv, host)
			}
			p.addHost(h)
			if len(ups) == 0 && srv.ret != "" {
				if target := nginxReturnTarget(srv.ret, host); target != "" {
					p.addRedirect(migrationRedirect{Hostname: host, Target: target, Status: nginxReturnStatus(srv.status), Enabled: true})
				}
			}
		}
	}
	if len(p.Hosts) == 0 && len(p.Redirects) == 0 {
		return nil, fmt.Errorf("no nginx server blocks with server_name and proxy_pass or return were found")
	}
	return p, nil
}

func nginxTokens(text string) []string {
	var tokens []string
	var word strings.Builder
	var quote rune
	comment := false
	flush := func() {
		if word.Len() > 0 {
			tokens = append(tokens, word.String())
			word.Reset()
		}
	}
	for _, r := range text {
		if comment {
			if r == '\n' {
				comment = false
			}
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				word.WriteRune(r)
			}
			continue
		}
		switch r {
		case '#':
			flush()
			comment = true
		case '\'', '"':
			quote = r
		case '{', '}', ';':
			flush()
			tokens = append(tokens, string(r))
		case ' ', '\t', '\n', '\r':
			flush()
		default:
			word.WriteRune(r)
		}
	}
	flush()
	return tokens
}

func nginxParse(tokens []string) (map[string][]string, []nginxServer, error) {
	upstreams := map[string][]string{}
	var servers []nginxServer
	var current *nginxServer
	var currentUpstream string
	var stack []string
	var stmt []string
	for _, token := range tokens {
		switch token {
		case "{":
			kind := "block"
			if len(stmt) > 0 {
				kind = stmt[0]
			}
			switch {
			case kind == "server":
				current = &nginxServer{}
			case kind == "upstream" && len(stmt) > 1:
				currentUpstream = stmt[1]
			}
			stack = append(stack, kind)
			stmt = nil
		case ";":
			if len(stmt) == 0 {
				continue
			}
			if len(stack) > 0 && stack[len(stack)-1] == "upstream" && stmt[0] == "server" && len(stmt) > 1 {
				upstreams[currentUpstream] = append(upstreams[currentUpstream], stmt[1])
			}
			if current != nil {
				nginxDirective(current, stmt)
			}
			stmt = nil
		case "}":
			if len(stack) == 0 {
				return nil, nil, fmt.Errorf("unbalanced braces")
			}
			kind := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if kind == "server" && current != nil {
				servers = append(servers, *current)
				current = nil
			}
			if kind == "upstream" {
				currentUpstream = ""
			}
			stmt = nil
		default:
			stmt = append(stmt, token)
		}
	}
	if len(stack) != 0 {
		return nil, nil, fmt.Errorf("unclosed block")
	}
	return upstreams, servers, nil
}

func nginxDirective(srv *nginxServer, stmt []string) {
	switch stmt[0] {
	case "server_name":
		for _, raw := range stmt[1:] {
			host := strings.ToLower(strings.TrimSpace(raw))
			if host == "" || host == "_" || strings.HasPrefix(host, "~") {
				continue
			}
			srv.hosts = appendUnique(srv.hosts, host)
		}
	case "listen":
		for _, arg := range stmt[1:] {
			if arg == "ssl" || strings.HasSuffix(arg, ":443") || arg == "443" {
				srv.tls = true
			}
		}
	case "ssl_certificate":
		if len(stmt) > 1 {
			srv.cert = strings.Trim(stmt[1], `"'`)
		}
	case "ssl_certificate_key":
		if len(stmt) > 1 {
			srv.key = strings.Trim(stmt[1], `"'`)
		}
	case "proxy_pass":
		if len(stmt) > 1 {
			target := strings.Trim(stmt[1], `"'`)
			if srv.proxy != "" && srv.proxy != target {
				srv.proxyN++
			}
			srv.proxy = target
		}
	case "return":
		if len(stmt) > 1 {
			if code, err := strconv.Atoi(stmt[1]); err == nil && code >= 300 && code <= 399 {
				srv.status = code
				if len(stmt) > 2 {
					srv.ret = stmt[2]
				}
			} else {
				srv.ret = stmt[1]
			}
		}
	}
}

func nginxProxyURLs(target string, upstreams map[string][]string) []string {
	target = strings.TrimSpace(target)
	if target == "" || strings.Contains(target, "$") {
		return nil
	}
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil
	}
	if servers, ok := upstreams[u.Host]; ok && len(servers) > 0 {
		var out []string
		for _, server := range servers {
			out = appendUnique(out, u.Scheme+"://"+server)
		}
		return out
	}
	return []string{target}
}

func nginxReturnTarget(raw, host string) string {
	target := strings.TrimSpace(raw)
	if target == "" {
		return ""
	}
	target = strings.ReplaceAll(target, "$host", host)
	target = strings.ReplaceAll(target, "$server_name", host)
	target = strings.ReplaceAll(target, "$request_uri", "$path")
	target = strings.ReplaceAll(target, "$uri", "$path")
	probe := strings.ReplaceAll(target, "$path", "")
	u, err := url.Parse(probe)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return target
}

func nginxReturnStatus(code int) int {
	switch code {
	case 301, 302, 307, 308:
		return code
	}
	return 302
}

func addNginxCert(p *migrationPreview, files map[string][]byte, srv nginxServer, host string) {
	for i := range p.Certificates {
		if p.Certificates[i].Ref != srv.cert {
			continue
		}
		if !containsString(p.Certificates[i].Hosts, host) {
			p.Certificates[i].Hosts = append(p.Certificates[i].Hosts, host)
		}
		return
	}
	row := migrationCertificate{Ref: srv.cert, Domains: strings.Join(srv.hosts, ", "), Provider: "upload", Hosts: []string{host}}
	if migrationFindFile(files, srv.cert) != nil && migrationFindFile(files, srv.key) != nil {
		row.Importable = true
	} else {
		row.Problem = "the certificate and key files are not in the upload"
	}
	p.Certificates = append(p.Certificates, row)
}
