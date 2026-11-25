package api

import (
	"fmt"
	"path"
	"strings"
)

type haFrontend struct {
	name           string
	acls           map[string][]string
	uses           map[string]string
	defaultBackend string
	servers        []string
	tls            bool
	cert           string
}

func parseHAProxy(files map[string][]byte) (*migrationPreview, error) {
	p := &migrationPreview{Source: "haproxy"}
	backends := map[string][]string{}
	frontends := map[string]*haFrontend{}
	var order []string
	for name, body := range files {
		if !migrationFileMatch(name, ".cfg", ".conf", ".txt") && name != "config" {
			continue
		}
		section, kind := "", ""
		for _, raw := range strings.Split(migrationText(body), "\n") {
			line := strings.TrimSpace(stripHashComment(raw))
			if line == "" {
				continue
			}
			fields := strings.Fields(line)
			switch fields[0] {
			case "frontend", "listen":
				if len(fields) > 1 {
					kind, section = "frontend", fields[1]
					if frontends[section] == nil {
						frontends[section] = &haFrontend{name: section, acls: map[string][]string{}, uses: map[string]string{}}
						order = append(order, section)
					}
				}
				continue
			case "backend":
				if len(fields) > 1 {
					kind, section = "backend", fields[1]
				}
				continue
			case "global", "defaults", "resolvers", "userlist", "peers", "program", "cache":
				kind, section = "", ""
				continue
			}
			switch kind {
			case "frontend":
				f := frontends[section]
				switch fields[0] {
				case "acl":
					if len(fields) > 3 && (fields[2] == "hdr(host)" || fields[2] == "hdr_dom(host)") {
						var hosts []string
						for _, rawHost := range fields[3:] {
							if rawHost == "-i" || rawHost == "-m" || rawHost == "str" {
								continue
							}
							host := strings.ToLower(strings.Trim(rawHost, `"`))
							if host != "" {
								hosts = appendUnique(hosts, host)
							}
						}
						f.acls[fields[1]] = hosts
					}
				case "use_backend":
					if len(fields) > 3 && fields[2] == "if" {
						f.uses[fields[3]] = fields[1]
					}
				case "default_backend":
					if len(fields) > 1 {
						f.defaultBackend = fields[1]
					}
				case "bind":
					for i, arg := range fields {
						if arg == "ssl" || arg == "crt" {
							f.tls = true
						}
						if arg == "crt" && i+1 < len(fields) {
							f.cert = trimHAValue(fields[i+1])
						}
					}
				case "server":
					if len(fields) > 2 {
						f.servers = append(f.servers, haServerURL(fields[2], line))
					}
				case "http-request":
					if len(fields) > 2 && fields[1] == "redirect" {
						p.Notes = appendUnique(p.Notes, "HAProxy http-request redirects are not imported.")
					}
				}
			case "backend":
				if fields[0] == "server" && len(fields) > 2 {
					backends[section] = appendUnique(backends[section], haServerURL(fields[2], line))
				}
			}
		}
	}
	for _, name := range order {
		f := frontends[name]
		if len(f.uses) == 0 && len(f.servers) == 0 && f.defaultBackend == "" {
			p.Skipped = append(p.Skipped, name+": no host ACL or servers")
			continue
		}
		if len(f.uses) == 0 && f.defaultBackend != "" && len(f.aclsHosts()) == 0 {
			p.Notes = appendUnique(p.Notes, "HAProxy frontend "+name+" uses a default backend without a host ACL; it cannot be mapped to a hostname.")
		}
		for acl, backend := range f.uses {
			hosts := f.acls[acl]
			if len(hosts) == 0 {
				p.Skipped = append(p.Skipped, name+" use_backend "+backend+" has no hdr(host) ACL")
				continue
			}
			ups := f.servers
			if len(ups) == 0 {
				ups = backends[backend]
			}
			for _, host := range hosts {
				h := f.migrationHost(host, ups)
				if h.CertRef != "" {
					addHACert(p, files, f.cert, host)
				}
				p.addHost(h)
			}
		}
		if len(f.uses) == 0 {
			ups := f.servers
			if len(ups) == 0 && f.defaultBackend != "" {
				ups = backends[f.defaultBackend]
			}
			for _, host := range f.aclsHosts() {
				h := f.migrationHost(host, ups)
				if h.CertRef != "" {
					addHACert(p, files, f.cert, host)
				}
				p.addHost(h)
			}
		}
	}
	if len(p.Hosts) == 0 && len(p.Skipped) == 0 {
		return nil, fmt.Errorf("no HAProxy frontend with hdr(host) ACLs was found")
	}
	return p, nil
}

func (f *haFrontend) migrationHost(host string, ups []string) migrationHost {
	h := migrationHost{Hostname: host, Upstreams: ups, Enabled: true, TLS: f.tls}
	if f.cert != "" {
		h.CertRef = f.cert
		h.CertName = path.Base(f.cert)
	}
	return h
}

func addHACert(p *migrationPreview, files map[string][]byte, ref, host string) {
	for i := range p.Certificates {
		if p.Certificates[i].Ref != ref {
			continue
		}
		if !containsString(p.Certificates[i].Hosts, host) {
			p.Certificates[i].Hosts = append(p.Certificates[i].Hosts, host)
		}
		return
	}
	row := migrationCertificate{Ref: ref, Domains: host, Provider: "upload", Hosts: []string{host}}
	bundle := migrationFindFile(files, ref)
	certPEM, keyPEM := splitPEMBundle(bundle)
	switch {
	case len(certPEM) > 0 && len(keyPEM) > 0:
		row.Importable = true
	case len(bundle) == 0:
		row.Problem = "the PEM bundle is not in the upload"
	default:
		row.Problem = "the PEM bundle needs a certificate and a private key"
	}
	p.Certificates = append(p.Certificates, row)
}

func trimHAValue(s string) string {
	return strings.Trim(strings.TrimSpace(s), `"'`)
}

func (f *haFrontend) aclsHosts() []string {
	var hosts []string
	for _, list := range f.acls {
		for _, host := range list {
			hosts = appendUnique(hosts, host)
		}
	}
	return hosts
}

func haServerURL(addr, line string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" || strings.HasPrefix(addr, "unix@") {
		return ""
	}
	scheme := "http"
	if strings.Contains(" "+line+" ", " ssl ") {
		scheme = "https"
	}
	if strings.Contains(addr, "://") {
		return addr
	}
	return scheme + "://" + addr
}
