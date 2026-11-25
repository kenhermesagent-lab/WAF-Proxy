package api

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// migrationFiles accepts a single config or a ZIP of configs. ZIP entry names
// are kept so certificate references inside a config can find sibling files.
func migrationFiles(data []byte) (map[string][]byte, error) {
	if !bytes.HasPrefix(data, []byte("PK")) {
		return map[string][]byte{"config": data}, nil
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("the upload is not a readable ZIP: %w", err)
	}
	files := map[string][]byte{}
	var total int64
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(rc, 4<<20))
		rc.Close()
		if err != nil {
			continue
		}
		total += int64(len(body))
		if total > 32<<20 {
			return nil, fmt.Errorf("the ZIP expands to more than 32 MB")
		}
		files[path.Clean(f.Name)] = body
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("the ZIP is empty")
	}
	return files, nil
}

func migrationText(data []byte) string {
	return strings.TrimPrefix(string(data), "\ufeff")
}

func migrationFileMatch(name string, extensions ...string) bool {
	lower := strings.ToLower(name)
	for _, ext := range extensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func migrationConfigBodies(files map[string][]byte, preferred []string, extensions ...string) [][]byte {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var bodies [][]byte
	used := map[string]bool{}
	for _, want := range preferred {
		for _, name := range names {
			if strings.EqualFold(path.Base(name), want) && !used[name] {
				bodies = append(bodies, files[name])
				used[name] = true
			}
		}
	}
	for _, name := range names {
		if used[name] || !migrationFileMatch(name, extensions...) {
			continue
		}
		bodies = append(bodies, files[name])
	}
	if len(bodies) == 0 && len(files) == 1 {
		for _, body := range files {
			bodies = append(bodies, body)
		}
	}
	return bodies
}

func migrationRegisterCertFile(p *migrationPreview, files map[string][]byte, certRef, keyRef string) bool {
	if certRef == "" || keyRef == "" {
		return false
	}
	certPEM := migrationFindFile(files, certRef)
	keyPEM := migrationFindFile(files, keyRef)
	importable := len(certPEM) > 0 && len(keyPEM) > 0
	row := migrationCertificate{Ref: certRef, Domains: certificateDomains(certPEM), Provider: "upload", Importable: importable}
	if !importable {
		row.Problem = "the certificate and key files are not both in the upload"
	}
	seen := false
	for _, c := range p.Certificates {
		if c.Ref == certRef {
			seen = true
			break
		}
	}
	if !seen {
		p.Certificates = append(p.Certificates, row)
	}
	return importable
}

func migrationAddCertHost(p *migrationPreview, ref, host string) {
	for i := range p.Certificates {
		if p.Certificates[i].Ref == ref && !containsString(p.Certificates[i].Hosts, host) {
			p.Certificates[i].Hosts = append(p.Certificates[i].Hosts, host)
			return
		}
	}
}

func migrationFindFile(files map[string][]byte, ref string) []byte {
	ref = strings.TrimPrefix(path.Clean("/"+ref), "/")
	for name, body := range files {
		clean := path.Clean(name)
		if clean == ref || strings.HasSuffix(clean, "/"+ref) || strings.HasSuffix("/"+ref, "/"+clean) {
			return body
		}
	}
	return nil
}
