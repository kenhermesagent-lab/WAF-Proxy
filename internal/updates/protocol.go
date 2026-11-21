package updates

import (
	"os"
	"path/filepath"
	"regexp"
)

// DefaultHelperSocket is created by the root-only update helper installed by
// the native installer or the Docker host-updater installer. The console
// service connects to it and never runs apt or a build itself.
const DefaultHelperSocket = "/run/wafproxy-updates/updates.sock"

const (
	HelperActionPing      = "ping"
	HelperActionCheck     = "check"
	HelperActionApply     = "apply"
	HelperActionAppCheck  = "app-check"
	HelperActionAppUpdate = "app-update"
	// HelperActionAppStatus reports the host's recorded checkout and installed
	// updater scripts. A Docker install cannot see those paths from inside the
	// container, so the console asks the helper instead of stat()ing its own
	// filesystem before offering the Update button.
	HelperActionAppStatus = "app-status"
	// HelperActionAppConfigure records the checkout the helper rebuilds, for a
	// host whose install lives outside the path install.sh recorded.
	HelperActionAppConfigure = "app-configure"
	// CrowdSec actions: install the engine and configure the bouncer, then
	// enroll the engine in the operator's CrowdSec account.
	HelperActionCrowdSecInstall = "crowdsec-install"
	HelperActionCrowdSecEnroll  = "crowdsec-enroll"
	// CrowdSecStatus reads `cscli console status`. It runs through the helper
	// because the credential files it reads are root-only, and the console
	// service is unprivileged.
	HelperActionCrowdSecStatus = "crowdsec-status"
	// CrowdSecDecisions reads `cscli metrics show decisions`: the aggregated
	// decisions the engine is enforcing, including console blocklists.
	HelperActionCrowdSecDecisions = "crowdsec-decisions"
	// CrowdSecRestart restarts the engine, which is how an accepted console
	// enrollment takes effect.
	HelperActionCrowdSecRestart = "crowdsec-restart"
)

// The self-update scripts are installed root-owned by deploy/install.sh. They
// use the checkout recorded at install time, so a public repository needs no
// credentials and a private fork can use the owner's existing git auth. They
// accept no argument from the browser.
var (
	AppSelfUpdateScript = firstScript("/usr/local/waf-proxy/lib/self-update", "/usr/local/lib/wafproxy/self-update")
	AppCheckScript      = firstScript("/usr/local/waf-proxy/lib/self-update-check", "/usr/local/lib/wafproxy/self-update-check")
	// CrowdSecInstallScript installs and configures the Security Engine. It
	// takes no argument: the browser never supplies a command, URL or package.
	CrowdSecInstallScript = firstScript("/usr/local/waf-proxy/lib/crowdsec-install", "/usr/local/lib/wafproxy/crowdsec-install")
)

// UpdateScript is one fixed script install.sh installs on the host.
type UpdateScript struct {
	Name string
	Path string
}

// UpdateScripts lists the installed updater scripts the helper needs.
func UpdateScripts() []UpdateScript {
	return []UpdateScript{
		{"self-update", AppSelfUpdateScript},
		{"self-update-check", AppCheckScript},
	}
}

// MissingUpdateScripts names the updater scripts that are not installed. The
// console reports the Update button unavailable while any are absent instead of
// failing when an admin clicks it.
func MissingUpdateScripts() []string {
	var missing []string
	for _, script := range UpdateScripts() {
		if info, err := os.Stat(script.Path); err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			missing = append(missing, script.Name)
		}
	}
	return missing
}

// firstScript keeps a host installed before 1.3.2 working until install.sh is
// re-run; those releases kept the helper scripts under /usr/local/lib/wafproxy.
func firstScript(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return paths[0]
}

// HelperRequest is deliberately tiny. The helper accepts only the fixed actions
// above and an exact package from the compiled catalog.
type HelperRequest struct {
	Action  string `json:"action"`
	Package string `json:"package,omitempty"`
	// Key carries a CrowdSec console enrollment key. The helper rejects any
	// value ValidConsoleKey does not accept and passes it as a single argv
	// entry, so it can never become part of a command line.
	Key string `json:"key,omitempty"`
	// Path is the absolute directory of a WAF-Proxy checkout, accepted only by
	// app-configure and validated as a git checkout with the deploy scripts.
	Path string `json:"path,omitempty"`
}

type HelperResponse struct {
	OK     bool   `json:"ok"`
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
	// The app-status reply describes the host filesystem the helper shares
	// with the installer.
	SourceDir      string   `json:"source_dir,omitempty"`
	Mode           string   `json:"mode,omitempty"`
	CheckoutExists bool     `json:"checkout_exists,omitempty"`
	MissingScripts []string `json:"missing_scripts,omitempty"`
}

var consoleKeyRE = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{16,256}$`)

// ValidConsoleKey accepts the shape of a CrowdSec console enrollment key.
func ValidConsoleKey(key string) bool { return consoleKeyRE.MatchString(key) }

// HelperSocketPath returns the configured socket, defaulting to the path the
// installer creates.
func HelperSocketPath() string {
	if v := osGetenv("WAFPROXY_UPDATE_SOCKET"); v != "" {
		return filepath.Clean(v)
	}
	return DefaultHelperSocket
}
