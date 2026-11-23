package bundle

import (
	"fmt"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

// CatalogProvider labels the packs that ship inside the binary instead of
// arriving through a signed channel.
const CatalogProvider = "builtin"

// CatalogEntry is one signature pack shipped with the release. The packs are
// "known good" because they are compiled into this build and checked with
// ValidateBundle and ValidateCompile at startup, not fetched from a mirror.
// Each one starts switched off: an administrator enables it from the console,
// and the profile mode still decides whether a match logs or blocks.
type CatalogEntry struct {
	Name        string           `json:"name"`
	Version     string           `json:"version"`
	Description string           `json:"description"`
	Rules       []waf.BundleRule `json:"-"`
}

var catalog = []CatalogEntry{
	{
		Name:        "secret-probes",
		Version:     "1",
		Description: "Direct requests for environment files, Git metadata, cloud credentials and database dumps.",
		Rules: []waf.BundleRule{
			{ID: 990101, Message: "Request for an environment file", Severity: "CRITICAL", Tag: "leak", Target: "REQUEST_FILENAME", Operator: `@rx (?i)(^|/)\.env([.-][a-z0-9_]+)?$`},
			{ID: 990102, Message: "Request for Git configuration or objects", Severity: "CRITICAL", Tag: "leak", Target: "REQUEST_FILENAME", Operator: `@rx (?i)(^|/)\.git/(config|head|index|packed-refs|refs/|objects/)`},
			{ID: 990103, Message: "Request for an SSH private key", Severity: "CRITICAL", Tag: "leak", Target: "REQUEST_FILENAME", Operator: `@rx (?i)(^|/)\.ssh/id_(rsa|dsa|ecdsa|ed25519)$`},
			{ID: 990104, Message: "Request for the AWS credential file", Severity: "CRITICAL", Tag: "leak", Target: "REQUEST_FILENAME", Operator: `@rx (?i)(^|/)\.aws/credentials$`},
			{ID: 990105, Message: "Request for a WordPress config backup", Severity: "ERROR", Tag: "leak", Target: "REQUEST_FILENAME", Operator: `@rx (?i)(^|/)wp-config\.php\.(bak|old|orig|save|swp|txt)$`},
			{ID: 990106, Message: "Request for a database or site archive", Severity: "ERROR", Tag: "leak", Target: "REQUEST_FILENAME", Operator: `@rx (?i)(^|/)(backup|dump|database|db)\.(sql|sqlite|sqlite3|zip|tar|tgz|gz)$`},
		},
	},
	{
		Name:        "exploit-payloads",
		Version:     "1",
		Description: "Log4Shell, Shellshock and Spring4Shell probes in headers, arguments and the body.",
		Rules: []waf.BundleRule{
			{ID: 990201, Message: "Log4Shell JNDI lookup", Severity: "CRITICAL", Tag: "rce", Target: "REQUEST_HEADERS|ARGS|REQUEST_BODY", Operator: `@rx (?i)\$\{jndi:(ldap|ldaps|rmi|dns|http|iiop)s?://`},
			{ID: 990202, Message: "Shellshock function definition in a header", Severity: "CRITICAL", Tag: "rce", Target: "REQUEST_HEADERS", Operator: `@rx ^\(\)\s*\{`},
			{ID: 990203, Message: "Spring4Shell classLoader probe", Severity: "CRITICAL", Tag: "rce", Target: "ARGS", Operator: `@rx (?i)class\.module\.classloader\.resources`},
			{ID: 990204, Message: "PHP stream wrapper in a parameter", Severity: "ERROR", Tag: "rce", Target: "ARGS", Operator: `@rx (?i)(php://(filter|input)|expect://|data://text/plain;base64)`},
		},
	},
	{
		Name:        "scanner-tools",
		Version:     "1",
		Description: "User agents of common web scanners and probes for router and NAS exploit paths.",
		Rules: []waf.BundleRule{
			{ID: 990301, Message: "Known web scanner user agent", Severity: "WARNING", Tag: "scanner", Target: "REQUEST_HEADERS", Operator: `@rx (?i)(sqlmap|nikto|nuclei|acunetix|nessus|masscan|zgrab|wpscan|dirbuster|gobuster|ffuf|whatweb)`},
			{ID: 990302, Message: "Probe for a router or NAS exploit path", Severity: "ERROR", Tag: "scanner", Target: "REQUEST_FILENAME", Operator: `@rx (?i)(^|/)(hnap1/|gponform/diag_form|cgi-bin/luci/|boaform/admin/formlogin)`},
		},
	},
}

// catalogPacks validates the shipped packs and returns them as WAF bundles.
// A release that ships a pack the engine refuses is a build error, so startup
// fails instead of serving a silently empty catalog.
func catalogPacks() ([]waf.Bundle, error) {
	out := make([]waf.Bundle, 0, len(catalog))
	for _, e := range catalog {
		b := waf.Bundle{Name: e.Name, Version: e.Version, Rules: e.Rules}
		if err := waf.ValidateBundle(b); err != nil {
			return nil, fmt.Errorf("catalog bundle %s: %w", e.Name, err)
		}
		if err := waf.ValidateCompile(e.Name, e.Rules); err != nil {
			return nil, fmt.Errorf("catalog bundle %s: %w", e.Name, err)
		}
		out = append(out, b)
	}
	return out, nil
}

func catalogRule(id int) (CatalogEntry, bool) {
	for _, e := range catalog {
		for _, r := range e.Rules {
			if r.ID == id {
				return e, true
			}
		}
	}
	return CatalogEntry{}, false
}

func catalogEntry(name string) (CatalogEntry, bool) {
	for _, e := range catalog {
		if e.Name == name {
			return e, true
		}
	}
	return CatalogEntry{}, false
}
