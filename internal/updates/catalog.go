package updates

import (
	_ "embed"
	"strings"
)

//go:embed host-packages.txt
var hostPackagesFile string

// CatalogEntry documents one host package the native service relies on.
type CatalogEntry struct {
	Name string
	Role string
}

var catalogRoles = map[string]string{
	"ca-certificates": "Trusted roots for ACME and upstream TLS",
	"nftables":        "Kernel-mode ban enforcement (nft)",
	"tzdata":          "Host time-zone data used by the console",
	"curl":            "Installers, self-update and the CrowdSec key check",
	"openssl":         "Certificates and bouncer key generation",
	"git":             "In-console application update (git pull)",
	"crowdsec":        "Security Engine behind the bouncer (optional)",
	"tailscale":       "Tailscale daemon for remote access (optional)",
}

// Catalog returns the fixed package allowlist embedded in both binaries.
func Catalog() []CatalogEntry {
	out := []CatalogEntry{}
	for _, line := range strings.Split(hostPackagesFile, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// The helper re-validates names before passing them to apt. Keeping the
		// character set tight prevents option injection even before that check.
		if !validPackageName(line) {
			continue
		}
		out = append(out, CatalogEntry{Name: line, Role: catalogRoles[line]})
	}
	return out
}

func validPackageName(name string) bool {
	if name == "" || len(name) > 80 {
		return false
	}
	for i, r := range name {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.' {
			if i == 0 && (r == '+' || r == '-' || r == '.') {
				return false
			}
			continue
		}
		return false
	}
	return true
}
