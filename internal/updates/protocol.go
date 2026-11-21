package updates

import "path/filepath"

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
)

// The self-update scripts are installed root-owned by deploy/install.sh. They
// use the checkout recorded at install time, so a private repository's existing
// git credentials work, and they accept no argument from the browser.
const (
	AppSelfUpdateScript = "/usr/local/lib/wafproxy/self-update"
	AppCheckScript      = "/usr/local/lib/wafproxy/self-update-check"
)

// HelperRequest is deliberately tiny. The helper accepts only the fixed actions
// above and an exact package from the compiled catalog.
type HelperRequest struct {
	Action  string `json:"action"`
	Package string `json:"package,omitempty"`
}

type HelperResponse struct {
	OK     bool   `json:"ok"`
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

// HelperSocketPath returns the configured socket, defaulting to the path the
// installer creates.
func HelperSocketPath() string {
	if v := osGetenv("WAFPROXY_UPDATE_SOCKET"); v != "" {
		return filepath.Clean(v)
	}
	return DefaultHelperSocket
}
