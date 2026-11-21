package updates

import "path/filepath"

// DefaultHelperSocket is created by the root-only update helper installed on a
// native deployment. The console service connects to it; it never runs apt
// itself, because the service unit has NoNewPrivileges=yes.
const DefaultHelperSocket = "/run/wafproxy-updates/updates.sock"

const (
	HelperActionPing  = "ping"
	HelperActionCheck = "check"
	HelperActionApply = "apply"
)

// HelperRequest is deliberately tiny. The helper accepts only the three fixed
// actions above and an exact package from the compiled catalog.
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
