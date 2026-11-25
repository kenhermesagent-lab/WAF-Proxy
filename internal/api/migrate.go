package api

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/rbac"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/urlguard"
)

// Migration imports hostnames from another reverse proxy. The preview is the
// unit of work: it is read-only, names every hostname that cannot be created,
// and the apply call sends back only the rows the operator kept. Nothing is
// overwritten: an existing hostname is reported and skipped.
const maxMigrationUpload = 10 << 20

type migrationRequest struct {
	Source   string `json:"source"` // npm | zoraxy | traefik | caddy | nginx | haproxy | apache
	Mode     string `json:"mode"`   // live | upload
	URL      string `json:"url"`
	Username string `json:"username"`
	Secret   string `json:"secret"`
	Insecure bool   `json:"insecure"`
	Content  string `json:"content"` // base64, upload mode
}

type migrationHost struct {
	Hostname   string   `json:"hostname"`
	Upstreams  []string `json:"upstreams"`
	Enabled    bool     `json:"enabled"`
	TLS        bool     `json:"tls"`
	AccessList string   `json:"access_list,omitempty"`
	CertRef    string   `json:"cert_ref,omitempty"`
	CertKeyRef string   `json:"cert_key_ref,omitempty"`
	CertName   string   `json:"cert_name,omitempty"`
	Exists     bool     `json:"exists"`
	Problem    string   `json:"problem,omitempty"`
}

type migrationRedirect struct {
	Hostname string `json:"hostname"`
	Target   string `json:"target"`
	Status   int    `json:"status"`
	Enabled  bool   `json:"enabled"`
	Exists   bool   `json:"exists"`
	Problem  string `json:"problem,omitempty"`
}

type migrationAccessList struct {
	Name      string   `json:"name"`
	Allow     []string `json:"allow"`
	Deny      []string `json:"deny"`
	AuthUsers int      `json:"auth_users"`
}

// migrationCertificate is preview metadata only. Keys never leave the server:
// apply re-reads them from the source once the operator confirms the import.
type migrationCertificate struct {
	Ref        string   `json:"ref"`
	Domains    string   `json:"domains"`
	Provider   string   `json:"provider"`
	Hosts      []string `json:"hosts,omitempty"`
	Importable bool     `json:"importable"`
	Problem    string   `json:"problem,omitempty"`
}

type migrationPreview struct {
	Source       string                 `json:"source"`
	Hosts        []migrationHost        `json:"hosts"`
	Redirects    []migrationRedirect    `json:"redirects"`
	AccessLists  []migrationAccessList  `json:"access_lists"`
	Certificates []migrationCertificate `json:"certificates"`
	Notes        []string               `json:"notes"`
	Skipped      []string               `json:"skipped"`
}

// migrationApply carries only the rows the operator kept, plus the source
// connection so certificates can be fetched without sending private keys
// through the browser.
type migrationApply struct {
	Source      string                `json:"source"`
	Hosts       []migrationHost       `json:"hosts"`
	Redirects   []migrationRedirect   `json:"redirects"`
	AccessLists []migrationAccessList `json:"access_lists"`
	Connection  migrationRequest      `json:"connection"`
}

type migrationResult struct {
	Created      int      `json:"created"`
	Redirects    int      `json:"redirects"`
	AccessLists  int      `json:"access_lists"`
	Certificates int      `json:"certificates"`
	Skipped      int      `json:"skipped"`
	Problems     []string `json:"problems"`
}

func (s *Server) previewMigration(w http.ResponseWriter, r *http.Request) {
	var in migrationRequest
	if err := decodeLimit(r, &in, 14<<20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	p, err := s.loadMigration(r, in)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.enrichMigration(r, p))
}

func (s *Server) loadMigration(r *http.Request, in migrationRequest) (*migrationPreview, error) {
	in.Source = strings.ToLower(strings.TrimSpace(in.Source))
	in.Mode = strings.ToLower(strings.TrimSpace(in.Mode))
	switch in.Source {
	case "npm":
		switch in.Mode {
		case "live":
			return s.fetchNPM(r, in)
		case "upload":
			data, err := migrationUpload(in)
			if err != nil {
				return nil, err
			}
			p, err := parseNPMExport(data)
			if err != nil {
				return nil, err
			}
			return p, nil
		}
		return nil, fmt.Errorf("choose live or upload")
	case "zoraxy":
		if in.Mode == "live" {
			return nil, fmt.Errorf("a live Zoraxy connection is not available yet; export its configuration ZIP and upload it")
		}
		data, err := migrationUpload(in)
		if err != nil {
			return nil, err
		}
		return parseZoraxyZIP(data)
	case "traefik":
		if in.Mode == "live" {
			return s.fetchTraefik(r, in)
		}
		data, err := migrationUpload(in)
		if err != nil {
			return nil, err
		}
		return parseTraefik(data)
	case "caddy":
		if in.Mode == "live" {
			return s.fetchCaddy(r, in)
		}
		data, err := migrationUpload(in)
		if err != nil {
			return nil, err
		}
		return parseCaddy(data)
	case "nginx":
		return migrationParsedUpload(in, parseNginx)
	case "haproxy":
		return migrationParsedUpload(in, parseHAProxy)
	case "apache":
		return migrationParsedUpload(in, parseApache)
	}
	return nil, fmt.Errorf("unknown migration source")
}

func migrationParsedUpload(in migrationRequest, parse func(map[string][]byte) (*migrationPreview, error)) (*migrationPreview, error) {
	data, err := migrationUpload(in)
	if err != nil {
		return nil, err
	}
	files, err := migrationFiles(data)
	if err != nil {
		return nil, err
	}
	return parse(files)
}

func migrationUpload(in migrationRequest) ([]byte, error) {
	raw := strings.TrimSpace(in.Content)
	if i := strings.Index(raw, ","); strings.HasPrefix(raw, "data:") && i >= 0 {
		raw = raw[i+1:]
	}
	if raw == "" {
		return nil, fmt.Errorf("choose a file to upload")
	}
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("the upload is not valid base64")
	}
	if len(data) == 0 || len(data) > maxMigrationUpload {
		return nil, fmt.Errorf("the upload must be between 1 byte and 10 MB")
	}
	return data, nil
}

// ---------- NPM ----------

type npmHost struct {
	DomainNames    []string `json:"domain_names"`
	ForwardScheme  string   `json:"forward_scheme"`
	ForwardHost    string   `json:"forward_host"`
	ForwardPort    int      `json:"forward_port"`
	Enabled        *bool    `json:"enabled"`
	SSLForced      bool     `json:"ssl_forced"`
	CertificateID  int64    `json:"certificate_id"`
	AccessListID   int64    `json:"access_list_id"`
	AdvancedConfig string   `json:"advanced_config"`
}

type npmAccessClient struct {
	Address   string `json:"address"`
	Directive string `json:"directive"`
}

type npmAccessList struct {
	ID      int64             `json:"id"`
	Name    string            `json:"name"`
	Clients []npmAccessClient `json:"clients"`
	Items   []struct {
		Username string `json:"username"`
	} `json:"items"`
}

type npmRedirect struct {
	DomainNames       []string `json:"domain_names"`
	ForwardScheme     string   `json:"forward_scheme"`
	ForwardDomainName string   `json:"forward_domain_name"`
	ForwardHTTPCode   int      `json:"forward_http_code"`
	PreservePath      bool     `json:"preserve_path"`
	Enabled           *bool    `json:"enabled"`
}

type npmCertificate struct {
	ID          int64    `json:"id"`
	Provider    string   `json:"provider"`
	NiceName    string   `json:"nice_name"`
	DomainNames []string `json:"domain_names"`
	ExpiresOn   string   `json:"expires_on"`
	Meta        struct {
		Certificate    string `json:"certificate"`
		CertificateKey string `json:"certificate_key"`
	} `json:"meta"`
}

type npmExport struct {
	ProxyHosts       []npmHost       `json:"proxy_hosts"`
	AccessLists      []npmAccessList `json:"access_lists"`
	RedirectionHosts []npmRedirect   `json:"redirection_hosts"`
}

func parseNPMExport(data []byte) (*migrationPreview, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("the file is empty")
	}
	var exp npmExport
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &exp.ProxyHosts); err != nil {
			return nil, fmt.Errorf("the JSON is not an NPM proxy-host list: %w", err)
		}
	} else if err := json.Unmarshal(trimmed, &exp); err != nil {
		return nil, fmt.Errorf("the JSON is not an NPM export: %w", err)
	}
	if len(exp.ProxyHosts) == 0 && len(exp.RedirectionHosts) == 0 {
		return nil, fmt.Errorf("no proxy or redirection hosts found in the file")
	}
	return previewFromNPM(exp.ProxyHosts, exp.AccessLists, exp.RedirectionHosts, nil), nil
}

func previewFromNPM(hosts []npmHost, lists []npmAccessList, redirects []npmRedirect, certs []npmCertificate) *migrationPreview {
	p := &migrationPreview{Source: "npm"}
	certByID := map[int64]npmCertificate{}
	for _, c := range certs {
		certByID[c.ID] = c
	}
	certRows := map[int64]*migrationCertificate{}
	byID := map[int64]string{}
	for _, l := range lists {
		name := strings.TrimSpace(l.Name)
		if name == "" {
			name = "NPM list " + strconv.FormatInt(l.ID, 10)
		}
		al := migrationAccessList{Name: name, AuthUsers: len(l.Items)}
		for _, c := range l.Clients {
			addr := strings.TrimSpace(c.Address)
			if addr == "" {
				continue
			}
			if strings.EqualFold(c.Directive, "allow") {
				al.Allow = append(al.Allow, addr)
			} else {
				al.Deny = append(al.Deny, addr)
			}
		}
		byID[l.ID] = name
		p.AccessLists = append(p.AccessLists, al)
		if al.AuthUsers > 0 {
			p.Notes = appendUnique(p.Notes, "NPM basic-auth users are not imported; recreate them with an access gate if a host needs a login.")
		}
	}
	for _, h := range hosts {
		scheme := strings.TrimSpace(h.ForwardScheme)
		if scheme == "" {
			scheme = "http"
		}
		upstream := ""
		if host := strings.TrimSpace(h.ForwardHost); host != "" {
			host = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(host, "http://"), "https://"), "/")
			if h.ForwardPort > 0 {
				host = net.JoinHostPort(host, strconv.Itoa(h.ForwardPort))
			}
			upstream = scheme + "://" + host
		}
		enabled := h.Enabled == nil || *h.Enabled
		certName, certRef := "", ""
		cert, hasCert := certByID[h.CertificateID]
		if h.CertificateID > 0 {
			certRef = "npm:" + strconv.FormatInt(h.CertificateID, 10)
			if hasCert {
				certName = strings.TrimSpace(cert.NiceName)
				if certName == "" {
					certName = strings.Join(cert.DomainNames, ", ")
				}
			} else {
				certName = "NPM certificate #" + strconv.FormatInt(h.CertificateID, 10)
			}
		}
		for _, domain := range h.DomainNames {
			host := strings.ToLower(strings.TrimSpace(domain))
			if host == "" {
				continue
			}
			if hasCert {
				addNPMCertificate(certRows, cert, host)
			}
			mh := migrationHost{
				Hostname: host, Enabled: enabled,
				TLS:        h.SSLForced || h.CertificateID > 0,
				AccessList: byID[h.AccessListID], CertRef: certRef, CertName: certName,
			}
			if upstream != "" {
				mh.Upstreams = []string{upstream}
			}
			p.Hosts = append(p.Hosts, mh)
		}
		if h.AdvancedConfig != "" {
			p.Notes = appendUnique(p.Notes, "NPM advanced nginx configuration is not imported; review those hosts after the move.")
		}
	}
	seenCert := map[string]bool{}
	for _, h := range p.Hosts {
		if h.CertRef == "" || seenCert[h.CertRef] {
			continue
		}
		seenCert[h.CertRef] = true
		id, _ := strconv.ParseInt(strings.TrimPrefix(h.CertRef, "npm:"), 10, 64)
		if row := certRows[id]; row != nil {
			p.Certificates = append(p.Certificates, *row)
		}
	}
	for _, rd := range redirects {
		scheme := strings.TrimSpace(rd.ForwardScheme)
		if scheme == "" {
			scheme = "http"
		}
		target := scheme + "://" + strings.TrimSpace(rd.ForwardDomainName)
		if rd.PreservePath {
			target += "$path"
		}
		status := rd.ForwardHTTPCode
		switch status {
		case 301, 302, 307, 308:
		default:
			status = 301
		}
		enabled := rd.Enabled == nil || *rd.Enabled
		for _, domain := range rd.DomainNames {
			host := strings.ToLower(strings.TrimSpace(domain))
			if host == "" {
				continue
			}
			p.Redirects = append(p.Redirects, migrationRedirect{Hostname: host, Target: target, Status: status, Enabled: enabled})
		}
	}
	return p
}

func (s *Server) fetchNPM(r *http.Request, in migrationRequest) (*migrationPreview, error) {
	base, err := checkMigrationURL(in.URL)
	if err != nil {
		return nil, err
	}
	client := migrationHTTPClient(in.Insecure)
	token, err := npmLogin(r.Context(), client, base, in.Username, in.Secret)
	if err != nil {
		return nil, err
	}
	var hosts []npmHost
	var lists []npmAccessList
	var redirects []npmRedirect
	var certs []npmCertificate
	if err := migrationJSON(r.Context(), client, http.MethodGet, base+"/api/nginx/proxy-hosts", token, nil, &hosts); err != nil {
		return nil, fmt.Errorf("read NPM proxy hosts: %w", err)
	}
	listErr := migrationJSON(r.Context(), client, http.MethodGet, base+"/api/nginx/access-lists", token, nil, &lists)
	redirectErr := migrationJSON(r.Context(), client, http.MethodGet, base+"/api/nginx/redirection-hosts", token, nil, &redirects)
	certErr := migrationJSON(r.Context(), client, http.MethodGet, base+"/api/nginx/certificates", token, nil, &certs)
	p := previewFromNPM(hosts, lists, redirects, certs)
	if listErr != nil {
		p.Notes = appendUnique(p.Notes, "NPM access lists could not be read; those hosts are imported without them. "+listErr.Error())
	}
	if redirectErr != nil {
		p.Notes = appendUnique(p.Notes, "NPM redirections could not be read; no redirects were imported. "+redirectErr.Error())
	}
	if certErr != nil {
		p.Notes = appendUnique(p.Notes, "NPM certificates could not be read; hosts are imported without them. "+certErr.Error())
	}
	return p, nil
}

func npmLogin(ctx context.Context, client *http.Client, base, username, secret string) (string, error) {
	if strings.TrimSpace(username) == "" || secret == "" {
		return "", fmt.Errorf("NPM needs the administrator email and password")
	}
	body, _ := json.Marshal(map[string]string{"identity": strings.TrimSpace(username), "secret": secret})
	var login struct {
		Token string `json:"token"`
	}
	if err := migrationJSON(ctx, client, http.MethodPost, base+"/api/tokens", "", body, &login); err != nil {
		return "", fmt.Errorf("NPM sign-in failed: %w", err)
	}
	if login.Token == "" {
		return "", fmt.Errorf("NPM returned no token")
	}
	return login.Token, nil
}

func addNPMCertificate(rows map[int64]*migrationCertificate, c npmCertificate, host string) {
	row := rows[c.ID]
	if row == nil {
		row = &migrationCertificate{
			Ref: "npm:" + strconv.FormatInt(c.ID, 10), Domains: strings.Join(c.DomainNames, ", "),
			Provider: c.Provider, Importable: true,
		}
		if c.Provider != "letsencrypt" && (c.Meta.Certificate == "" || c.Meta.CertificateKey == "") {
			row.Importable = false
			row.Problem = "NPM does not expose the private key for a custom certificate; re-upload it here"
		}
		if expires, ok := parseNPMTime(c.ExpiresOn); ok && time.Now().After(expires) {
			row.Importable = false
			row.Problem = "expired at the source"
		}
		rows[c.ID] = row
	}
	if !containsString(row.Hosts, host) {
		row.Hosts = append(row.Hosts, host)
	}
}

func parseNPMTime(raw string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05.000Z", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func (p *migrationPreview) addHost(h migrationHost) {
	if len(p.Redirects) > 0 {
		kept := p.Redirects[:0]
		for _, rd := range p.Redirects {
			if rd.Hostname != h.Hostname {
				kept = append(kept, rd)
			}
		}
		p.Redirects = kept
	}
	for i := range p.Hosts {
		if p.Hosts[i].Hostname != h.Hostname {
			continue
		}
		seen := map[string]bool{}
		for _, up := range p.Hosts[i].Upstreams {
			seen[up] = true
		}
		for _, up := range h.Upstreams {
			if up != "" && !seen[up] {
				p.Hosts[i].Upstreams = append(p.Hosts[i].Upstreams, up)
				seen[up] = true
			}
		}
		p.Hosts[i].TLS = p.Hosts[i].TLS || h.TLS
		p.Hosts[i].Enabled = p.Hosts[i].Enabled || h.Enabled
		if h.CertRef != "" {
			p.Hosts[i].CertRef, p.Hosts[i].CertKeyRef, p.Hosts[i].CertName = h.CertRef, h.CertKeyRef, h.CertName
		}
		if h.AccessList != "" {
			p.Hosts[i].AccessList = h.AccessList
		}
		return
	}
	p.Hosts = append(p.Hosts, h)
}

func (p *migrationPreview) addRedirect(rd migrationRedirect) {
	for _, existing := range p.Hosts {
		if existing.Hostname == rd.Hostname && len(existing.Upstreams) > 0 {
			return
		}
	}
	for _, existing := range p.Redirects {
		if existing.Hostname == rd.Hostname {
			return
		}
	}
	p.Redirects = append(p.Redirects, rd)
}

func containsString(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

// ---------- Zoraxy ----------

type zoraxyOrigin struct {
	OriginIPOrDomain string `json:"OriginIpOrDomain"`
	RequireTLS       bool   `json:"RequireTLS"`
}

type zoraxyRule struct {
	ProxyType            int               `json:"ProxyType"`
	RootOrMatchingDomain string            `json:"RootOrMatchingDomain"`
	MatchingDomainAlias  []string          `json:"MatchingDomainAlias"`
	ActiveOrigins        []zoraxyOrigin    `json:"ActiveOrigins"`
	VirtualDirectories   []json.RawMessage `json:"VirtualDirectories"`
	AccessFilterUUID     string            `json:"AccessFilterUUID"`
	Disabled             bool              `json:"Disabled"`
}

func parseZoraxyZIP(data []byte) (*migrationPreview, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		if p, jerr := parseNPMExport(data); jerr == nil {
			return p, nil
		}
		return nil, fmt.Errorf("the upload is not a Zoraxy ZIP: %w", err)
	}
	p := &migrationPreview{Source: "zoraxy"}
	for _, f := range zr.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), ".config") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			p.Skipped = append(p.Skipped, f.Name+": cannot read")
			continue
		}
		body, err := io.ReadAll(io.LimitReader(rc, 2<<20))
		rc.Close()
		if err != nil {
			p.Skipped = append(p.Skipped, f.Name+": cannot read")
			continue
		}
		var rule zoraxyRule
		if err := json.Unmarshal(body, &rule); err != nil {
			p.Skipped = append(p.Skipped, f.Name+": not JSON")
			continue
		}
		if rule.ProxyType != 0 && rule.ProxyType != 1 {
			p.Skipped = append(p.Skipped, f.Name+": not an HTTP proxy rule")
			continue
		}
		var ups []string
		for _, o := range rule.ActiveOrigins {
			raw := strings.TrimSpace(o.OriginIPOrDomain)
			if raw == "" {
				continue
			}
			if !strings.Contains(raw, "://") {
				scheme := "http"
				if o.RequireTLS {
					scheme = "https"
				}
				raw = scheme + "://" + raw
			}
			ups = append(ups, raw)
		}
		domains := append([]string{rule.RootOrMatchingDomain}, rule.MatchingDomainAlias...)
		for _, domain := range domains {
			host := strings.ToLower(strings.TrimSpace(domain))
			if host == "" {
				continue
			}
			p.Hosts = append(p.Hosts, migrationHost{
				Hostname: host, Upstreams: ups, Enabled: !rule.Disabled,
			})
		}
		if len(rule.VirtualDirectories) > 0 {
			p.Notes = appendUnique(p.Notes, "Zoraxy virtual directories are not imported; recreate them as route rules where needed.")
		}
		if rule.AccessFilterUUID != "" && !strings.EqualFold(rule.AccessFilterUUID, "default") {
			p.Notes = appendUnique(p.Notes, "Zoraxy access filters are not imported; recreate the allow/deny rules here.")
		}
	}
	if len(p.Hosts) == 0 && len(p.Skipped) == 0 {
		return nil, fmt.Errorf("no proxy rules found in the Zoraxy ZIP")
	}
	return p, nil
}

// ---------- preview enrichment ----------

func (s *Server) enrichMigration(r *http.Request, p *migrationPreview) *migrationPreview {
	if p.Hosts == nil {
		p.Hosts = []migrationHost{}
	}
	if p.Redirects == nil {
		p.Redirects = []migrationRedirect{}
	}
	if p.AccessLists == nil {
		p.AccessLists = []migrationAccessList{}
	}
	if p.Certificates == nil {
		p.Certificates = []migrationCertificate{}
	}
	if p.Notes == nil {
		p.Notes = []string{}
	}
	if p.Skipped == nil {
		p.Skipped = []string{}
	}
	base, _ := s.db(r).GetSetting("base_domain")
	if base != "" {
		p.Notes = appendUnique(p.Notes, "Only hostnames under "+base+" can be created. Anything outside it is listed but cannot be imported.")
	}
	seen := map[string]bool{}
	for i := range p.Hosts {
		h := &p.Hosts[i]
		h.Hostname = strings.ToLower(strings.TrimSpace(h.Hostname))
		if h.Hostname == "" {
			h.Problem = "no hostname"
			continue
		}
		if seen[h.Hostname] {
			h.Problem = "duplicate hostname in the export"
			continue
		}
		seen[h.Hostname] = true
		if msg := s.validateHostname(r, h.Hostname); msg != "" {
			h.Problem = msg
			continue
		}
		if _, err := s.db(r).ProxyByHost(h.Hostname); err == nil {
			h.Exists = true
			continue
		}
		if len(h.Upstreams) == 0 {
			h.Problem = "no upstream in the export"
			continue
		}
		for _, up := range h.Upstreams {
			if err := urlguard.Check(up, urlguard.Upstream); err != nil {
				h.Problem = "upstream " + up + ": " + err.Error()
				break
			}
		}
		if h.TLS {
			importable := false
			for _, c := range p.Certificates {
				if c.Ref == h.CertRef && c.Importable {
					importable = true
				}
			}
			if h.CertRef == "" {
				p.Notes = appendUnique(p.Notes, "This source does not include certificate files; issue a certificate for those hostnames here after the move.")
			} else if !importable {
				p.Notes = appendUnique(p.Notes, "Some source certificates cannot be exported; those hostnames are imported without their certificate.")
			}
		}
	}
	for i := range p.Redirects {
		rd := &p.Redirects[i]
		rd.Hostname = strings.ToLower(strings.TrimSpace(rd.Hostname))
		if rd.Hostname == "" {
			rd.Problem = "no hostname"
			continue
		}
		if seen[rd.Hostname] {
			rd.Problem = "duplicate hostname in the export"
			continue
		}
		seen[rd.Hostname] = true
		if msg := s.validateHostname(r, rd.Hostname); msg != "" {
			rd.Problem = msg
			continue
		}
		if _, err := s.db(r).ProxyByHost(rd.Hostname); err == nil {
			rd.Exists = true
			continue
		}
		if !validMigrationRedirect(rd.Target) {
			rd.Problem = "redirect target must be an absolute http(s) URL"
		}
	}
	if len(p.Hosts) > 0 || len(p.Redirects) > 0 {
		p.Notes = appendUnique(p.Notes, "Existing hostnames are skipped, never overwritten.")
	}
	if sess := sessionFrom(r); sess != nil && !sessionCan(sess, rbac.Permission("certificates", "write")) {
		for _, c := range p.Certificates {
			if c.Importable {
				p.Notes = appendUnique(p.Notes, "Importing the listed certificates needs certificates.write; those hosts would import without them.")
				break
			}
		}
	}
	if sess := sessionFrom(r); sess != nil && len(p.AccessLists) > 0 && !sessionCan(sess, rbac.Permission("policies", "write")) {
		p.Notes = appendUnique(p.Notes, "Importing access lists needs policies.write; those hostnames would import without them.")
	}
	return p
}

func validMigrationRedirect(target string) bool {
	probe := strings.ReplaceAll(strings.TrimSpace(target), "$path", "")
	u, err := url.Parse(probe)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil
}

// ---------- apply ----------

func (s *Server) applyMigration(w http.ResponseWriter, r *http.Request) {
	var in migrationApply
	if err := decodeLimit(r, &in, 24<<20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if len(in.Hosts) > 1000 || len(in.Redirects) > 1000 || len(in.AccessLists) > 200 {
		writeError(w, http.StatusBadRequest, "too many rows in one import")
		return
	}
	result := migrationResult{Problems: []string{}}
	certIDs, certProblems := s.importMigrationCerts(r, in)
	result.Certificates = len(certIDs)
	result.Problems = append(result.Problems, certProblems...)
	profiles := map[string]*int64{}
	canWritePolicies := sessionCan(sessionFrom(r), rbac.Permission("policies", "write"))
	if len(in.AccessLists) > 0 && !canWritePolicies {
		result.Problems = append(result.Problems, "access lists were not imported: policies.write is required")
	}
	if canWritePolicies {
		for _, al := range in.AccessLists {
			id, problems := s.createMigrationAccessList(r, al)
			result.Problems = append(result.Problems, problems...)
			if id != nil {
				profiles[al.Name] = id
				result.AccessLists++
			}
		}
	}

	for _, h := range in.Hosts {
		if h.Exists || h.Problem != "" {
			result.Skipped++
			continue
		}
		if msg := s.validateHostname(r, h.Hostname); msg != "" {
			result.Problems = append(result.Problems, h.Hostname+": "+msg)
			result.Skipped++
			continue
		}
		if len(h.Upstreams) == 0 {
			result.Problems = append(result.Problems, h.Hostname+": no upstream")
			result.Skipped++
			continue
		}
		var ups []model.Upstream
		bad := ""
		for _, raw := range h.Upstreams {
			if err := urlguard.Check(raw, urlguard.Upstream); err != nil {
				bad = raw + ": " + err.Error()
				break
			}
			ups = append(ups, model.Upstream{URL: raw, Weight: 1, Enabled: true})
		}
		if bad != "" {
			result.Problems = append(result.Problems, h.Hostname+": "+bad)
			result.Skipped++
			continue
		}
		p := migrationProxy(h.Hostname)
		p.Enabled = h.Enabled
		if id, ok := certIDs[h.CertRef]; ok {
			if s.certCoversHost(r, id, h.Hostname) {
				p.CertID = &id
			} else {
				result.Problems = append(result.Problems, h.Hostname+": the imported certificate does not cover this hostname")
			}
		} else if h.CertRef != "" {
			result.Problems = append(result.Problems, h.Hostname+": certificate was not imported")
		}
		if h.AccessList != "" {
			if id := profiles[h.AccessList]; id != nil {
				p.AccessProfileID = id
			} else {
				result.Problems = append(result.Problems, h.Hostname+": access list "+h.AccessList+" was not selected, so the host was imported without it")
			}
		}
		id, err := s.db(r).CreateProxy(p)
		if err != nil {
			result.Problems = append(result.Problems, h.Hostname+": "+err.Error())
			result.Skipped++
			continue
		}
		if err := s.db(r).ReplaceUpstreams(id, ups); err != nil {
			result.Problems = append(result.Problems, h.Hostname+": upstreams could not be saved")
			result.Skipped++
			continue
		}
		result.Created++
	}

	for _, rd := range in.Redirects {
		if rd.Exists || rd.Problem != "" {
			result.Skipped++
			continue
		}
		if msg := s.validateHostname(r, rd.Hostname); msg != "" {
			result.Problems = append(result.Problems, rd.Hostname+": "+msg)
			result.Skipped++
			continue
		}
		if !validMigrationRedirect(rd.Target) {
			result.Problems = append(result.Problems, rd.Hostname+": invalid redirect target")
			result.Skipped++
			continue
		}
		status := rd.Status
		switch status {
		case 301, 302, 307, 308:
		default:
			status = 301
		}
		p := migrationProxy(rd.Hostname)
		p.Enabled = rd.Enabled
		id, err := s.db(r).CreateProxy(p)
		if err != nil {
			result.Problems = append(result.Problems, rd.Hostname+": "+err.Error())
			result.Skipped++
			continue
		}
		route := model.Route{Kind: model.RouteRedirect, Match: "", Target: rd.Target, Status: status}
		if err := s.db(r).ReplaceRoutes(id, []model.Route{route}); err != nil {
			result.Problems = append(result.Problems, rd.Hostname+": redirect could not be saved")
			result.Skipped++
			continue
		}
		result.Redirects++
	}

	s.reload(r.Context())
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "migration.apply",
		fmt.Sprintf("%d host(s), %d redirect(s), %d access list(s), %d certificate(s)", result.Created, result.Redirects, result.AccessLists, result.Certificates),
		clientIP(r))
	writeJSON(w, http.StatusOK, result)
}

func migrationProxy(hostname string) *model.Proxy {
	return &model.Proxy{
		Hostname: hostname, Enabled: true, GateMode: "off", Fingerprint: "strict",
		BotLevel: "light", WAFMode: "inherit", LBPolicy: "weighted_rr",
		HealthPath: "/", HealthExpect: "200-399",
	}
}

// createMigrationAccessList turns one source list into a whitelist and/or a
// blocklist plus one access profile. NPM allows mixed allow and deny clients;
// two lists keep the two meanings apart, and the profile attaches both.
func (s *Server) createMigrationAccessList(r *http.Request, al migrationAccessList) (*int64, []string) {
	name := strings.TrimSpace(al.Name)
	if name == "" {
		return nil, []string{"an access list in the export has no name"}
	}
	var ids []int64
	var problems []string
	add := func(kind, suffix string, entries []string) {
		if len(entries) == 0 {
			return
		}
		listName := migrationName(name + " " + suffix)
		if existing, err := s.migrationAccessListByName(r, listName); err == nil {
			if existing.Kind != kind {
				problems = append(problems, "access list "+listName+" exists with a different kind; reused nothing")
				return
			}
			ids = append(ids, existing.ID)
			return
		}
		l := &model.AccessList{Kind: kind, Name: listName, IPs: strings.Join(entries, ",")}
		if msg := normalizeAccessList(l); msg != "" {
			problems = append(problems, "access list "+name+": "+msg)
			return
		}
		if err := s.db(r).CreateAccessList(l); err != nil {
			problems = append(problems, "access list "+listName+": "+err.Error())
			return
		}
		ids = append(ids, l.ID)
	}
	add(model.ListKindAllow, "(allow)", al.Allow)
	add(model.ListKindBlock, "(deny)", al.Deny)

	if len(ids) == 0 {
		if al.AuthUsers > 0 {
			problems = append(problems, "access list "+name+" uses only basic-auth users; recreate it with an access gate")
		}
		return nil, problems
	}
	profileName := migrationName(name)
	if existing, ok := s.migrationProfileByName(r, profileName); ok {
		return &existing, problems
	}
	profile := &model.AccessProfile{Name: profileName, ListIDs: ids}
	if err := s.db(r).CreateAccessProfile(profile); err != nil {
		problems = append(problems, "access profile "+profileName+": "+err.Error())
		return nil, problems
	}
	return &profile.ID, problems
}

func (s *Server) migrationAccessListByName(r *http.Request, name string) (*model.AccessList, error) {
	list, err := s.db(r).ListAccessLists()
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].Name == name {
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("not found")
}

func (s *Server) migrationProfileByName(r *http.Request, name string) (int64, bool) {
	list, err := s.db(r).ListAccessProfiles()
	if err != nil {
		return 0, false
	}
	for _, p := range list {
		if p.Name == name {
			return p.ID, true
		}
	}
	return 0, false
}

func migrationName(s string) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) > 64 {
		return string(r[:64])
	}
	return s
}

func appendUnique(list []string, value string) []string {
	for _, v := range list {
		if v == value {
			return list
		}
	}
	return append(list, value)
}

// ---------- HTTP helpers ----------

func migrationHTTPClient(insecure bool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- the operator opted in for a LAN appliance
	}
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func checkMigrationURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("enter the proxy URL, for example http://192.168.1.10:81")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("the proxy URL must use http or https")
	}
	if u.User != nil {
		return "", fmt.Errorf("put credentials in the fields, not in the URL")
	}
	u.RawQuery, u.Fragment = "", ""
	base := strings.TrimRight(u.String(), "/")
	if err := urlguard.Check(base, urlguard.Policy{AllowPrivate: true, AllowLoopback: true}); err != nil {
		return "", err
	}
	return base, nil
}

func migrationJSON(ctx context.Context, client *http.Client, method, target, token string, body []byte, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.TrimSpace(string(data))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
	}
	if out == nil {
		return nil
	}
	// NPM returns a bare array on most versions and {"data": [...]} on others.
	if err := json.Unmarshal(data, out); err == nil {
		return nil
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil || len(envelope.Data) == 0 {
		return fmt.Errorf("unexpected JSON from the source")
	}
	return json.Unmarshal(envelope.Data, out)
}
