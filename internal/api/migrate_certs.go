package api

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/rbac"
)

// importMigrationCerts fetches certificate material only after the operator
// confirms an import. Preview responses carry names, never private keys.
func (s *Server) importMigrationCerts(r *http.Request, in migrationApply) (map[string]int64, []string) {
	refs := map[string]bool{}
	for _, h := range in.Hosts {
		if !h.Exists && h.Problem == "" && h.CertRef != "" {
			refs[h.CertRef] = true
		}
	}
	if len(refs) == 0 {
		return nil, nil
	}
	var pairs map[string][2][]byte
	var problems []string
	switch in.Source {
	case "npm":
		if in.Connection.Mode != "live" {
			return nil, []string{"certificates are only available from a live NPM connection; upload the JSON export without them"}
		}
		pairs, problems = s.fetchNPMCertPairs(r.Context(), in.Connection, refs)
	case "nginx", "apache", "traefik", "caddy":
		pairs, problems = migrationFileCertPairs(in, refs)
	case "haproxy":
		pairs, problems = migrationCombinedCertPairs(in, refs)
	default:
		return nil, nil
	}
	if len(pairs) > 0 && !sessionCan(sessionFrom(r), rbac.Permission("certificates", "write")) {
		return nil, append(problems, "certificates were not imported: certificates.write is required")
	}

	ids := map[string]int64{}
	for ref, pair := range pairs {
		id, err := s.storeMigrationCert(r, pair[0], pair[1])
		if err != nil {
			problems = append(problems, ref+": "+err.Error())
			continue
		}
		ids[ref] = id
	}
	if len(ids) > 0 {
		if m := s.certsFor(r); m != nil {
			_ = m.Load()
		}
	}
	return ids, problems
}

func migrationFileCertPairs(in migrationApply, refs map[string]bool) (map[string][2][]byte, []string) {
	data, err := migrationUpload(in.Connection)
	if err != nil {
		return nil, []string{err.Error()}
	}
	files, err := migrationFiles(data)
	if err != nil {
		return nil, []string{err.Error()}
	}
	keys := map[string]string{}
	for _, h := range in.Hosts {
		if h.CertRef != "" && h.CertKeyRef != "" {
			keys[h.CertRef] = h.CertKeyRef
		}
	}
	pairs := map[string][2][]byte{}
	var problems []string
	for ref := range refs {
		certPEM := migrationFindFile(files, ref)
		keyRef := keys[ref]
		if keyRef == "" {
			keyRef = siblingKeyPath(ref)
		}
		keyPEM := migrationFindFile(files, keyRef)
		if len(certPEM) == 0 || len(keyPEM) == 0 {
			problems = append(problems, ref+": the certificate and key files are not in the upload")
			continue
		}
		pairs[ref] = [2][]byte{certPEM, keyPEM}
	}
	return pairs, problems
}

func migrationCombinedCertPairs(in migrationApply, refs map[string]bool) (map[string][2][]byte, []string) {
	data, err := migrationUpload(in.Connection)
	if err != nil {
		return nil, []string{err.Error()}
	}
	files, err := migrationFiles(data)
	if err != nil {
		return nil, []string{err.Error()}
	}
	pairs := map[string][2][]byte{}
	var problems []string
	for ref := range refs {
		certPEM, keyPEM := splitPEMBundle(migrationFindFile(files, ref))
		if len(certPEM) == 0 || len(keyPEM) == 0 {
			problems = append(problems, ref+": the PEM bundle needs a certificate and a private key")
			continue
		}
		pairs[ref] = [2][]byte{certPEM, keyPEM}
	}
	return pairs, problems
}

func certificateDomains(certPEM []byte) string {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	names := cert.DNSNames
	if len(names) == 0 && cert.Subject.CommonName != "" {
		names = []string{cert.Subject.CommonName}
	}
	return strings.Join(names, ", ")
}

func certificateCoversHost(certPEM []byte, host string) bool {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	return cert.VerifyHostname(host) == nil
}

func splitPEMBundle(data []byte) ([]byte, []byte) {
	var cert, key []byte
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		switch {
		case strings.Contains(block.Type, "CERTIFICATE"):
			cert = append(cert, pem.EncodeToMemory(block)...)
		case strings.Contains(block.Type, "PRIVATE KEY"):
			key = append(key, pem.EncodeToMemory(block)...)
		}
		data = rest
	}
	return cert, key
}

func siblingKeyPath(ref string) string {
	dir := path.Dir(ref)
	switch strings.ToLower(path.Base(ref)) {
	case "fullchain.pem", "cert.pem", "certificate.pem":
		return path.Join(dir, "privkey.pem")
	case "certificate.crt":
		return path.Join(dir, "private.key")
	}
	return ""
}

func (s *Server) fetchNPMCertPairs(ctx context.Context, in migrationRequest, refs map[string]bool) (map[string][2][]byte, []string) {
	base, err := checkMigrationURL(in.URL)
	if err != nil {
		return nil, []string{err.Error()}
	}
	client := migrationHTTPClient(in.Insecure)
	token, err := npmLogin(ctx, client, base, in.Username, in.Secret)
	if err != nil {
		return nil, []string{err.Error()}
	}
	pairs := map[string][2][]byte{}
	var problems []string
	for ref := range refs {
		id, err := strconv.ParseInt(strings.TrimPrefix(ref, "npm:"), 10, 64)
		if err != nil || !strings.HasPrefix(ref, "npm:") {
			continue
		}
		data, err := migrationDownload(ctx, client, base+"/api/nginx/certificates/"+strconv.FormatInt(id, 10)+"/download", token)
		if err != nil {
			problems = append(problems, ref+": NPM cannot export this certificate: "+err.Error())
			continue
		}
		certPEM, keyPEM, err := npmCertificatePair(data)
		if err != nil {
			problems = append(problems, ref+": "+err.Error())
			continue
		}
		pairs[ref] = [2][]byte{certPEM, keyPEM}
	}
	return pairs, problems
}

func migrationDownload(ctx context.Context, client *http.Client, target, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.TrimSpace(string(data))
		if len(msg) > 160 {
			msg = msg[:160]
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
	}
	return data, nil
}

func npmCertificatePair(data []byte) ([]byte, []byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, nil, fmt.Errorf("NPM returned no certificate ZIP")
	}
	var fullchain, cert, chain, key []byte
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(rc, 1<<20))
		rc.Close()
		if err != nil {
			continue
		}
		switch strings.ToLower(path.Base(f.Name)) {
		case "fullchain.pem":
			fullchain = body
		case "cert.pem", "certificate.pem":
			cert = body
		case "chain.pem":
			chain = body
		case "privkey.pem", "key.pem":
			key = body
		}
	}
	if fullchain == nil {
		fullchain = append(append([]byte{}, cert...), chain...)
	}
	if len(fullchain) == 0 || len(key) == 0 {
		return nil, nil, fmt.Errorf("the NPM download did not contain fullchain.pem and privkey.pem")
	}
	return fullchain, key, nil
}

// storeMigrationCert validates a pair the same way an upload does, reuses an
// identical certificate, and otherwise stores it as an uploaded certificate so
// ACME never tries to renew it.
func (s *Server) certCoversHost(r *http.Request, id int64, host string) bool {
	row, err := s.db(r).GetCert(id)
	if err != nil {
		return false
	}
	pair, err := tls.X509KeyPair(row.CertPEM, row.KeyPEM)
	if err != nil {
		return false
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false
	}
	return leaf.VerifyHostname(host) == nil
}

func (s *Server) storeMigrationCert(r *http.Request, certPEM, keyPEM []byte) (int64, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return 0, fmt.Errorf("the certificate and key do not match")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return 0, fmt.Errorf("the certificate cannot be parsed")
	}
	if time.Now().After(leaf.NotAfter) {
		return 0, fmt.Errorf("the certificate expired on %s", leaf.NotAfter.Format("2006-01-02"))
	}
	names := leaf.DNSNames
	if len(names) == 0 && leaf.Subject.CommonName != "" {
		names = []string{leaf.Subject.CommonName}
	}
	if len(names) == 0 {
		return 0, fmt.Errorf("the certificate names no hostname")
	}
	for _, name := range names {
		if !validHostname(strings.TrimPrefix(strings.ToLower(name), "*.")) {
			return 0, fmt.Errorf("invalid domain in the certificate: %s", name)
		}
	}
	domains := strings.Join(names, ",")
	if list, err := s.db(r).ListCerts(); err == nil {
		for _, row := range list {
			if row.Domains != domains || row.Source != model.CertSourceUploaded {
				continue
			}
			full, err := s.db(r).GetCert(row.ID)
			if err == nil && bytes.Equal(full.CertPEM, certPEM) {
				return row.ID, nil
			}
		}
	}
	c := &model.Cert{
		Domains: domains, Provider: "upload", Status: "issued",
		Source: model.CertSourceUploaded, CertPEM: certPEM, KeyPEM: keyPEM,
		IssuedAt: &leaf.NotBefore, ExpiresAt: &leaf.NotAfter,
		Wildcard: strings.Contains(domains, "*."), RenewMode: model.CertRenewBeforeExpiry,
		Challenge: "upload",
	}
	return s.db(r).SaveCert(c)
}
