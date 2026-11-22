// Package preset holds starting configurations for applications that are
// commonly put behind the proxy. A preset is not a policy: it fills in a WAF
// profile so the operator edits a working starting point instead of a blank
// form, and it never enables anything the proxy cannot undo.
package preset

import "github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"

// Preset is one application's suggested configuration.
type Preset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Methods is the WAF profile's method allowlist. WebDAV verbs matter for
	// Nextcloud and are refused by the default list.
	Methods string `json:"methods"`
	// MaxBody is the request-body ceiling. The proxy buffers a body to inspect
	// it, so this also bounds how much memory one request can take.
	MaxBody int64 `json:"max_body"`
	// MaxResponse cuts a response that grows past this size. Applications that
	// stream media or sync files leave it at 0 and stream unbounded.
	MaxResponse int64  `json:"max_response"`
	LoginPaths  string `json:"login_paths"`
	LoginRPS    int    `json:"login_rps"`
	LoginBurst  int    `json:"login_burst"`
	AdminPaths  string `json:"admin_paths"`
	AdminIPs    string `json:"admin_ips"`
	// Exceptions are OWASP CRS rule IDs commonly reported as false positives by
	// this application. They are suggestions: check them in detect mode first.
	Exceptions string   `json:"exceptions"`
	Notes      []string `json:"notes"`
}

// privateRanges is the admin-path allowlist a preset starts from: the operator's
// own network. An admin path is refused for everyone else until it is edited.
const privateRanges = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1/32,::1/128"

var all = []Preset{
	{
		ID:          "nextcloud",
		Name:        "Nextcloud",
		Description: "File sync and share over WebDAV, with an admin area under /settings.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS,PROPFIND,PROPPATCH,MKCOL,COPY,MOVE,LOCK,UNLOCK,REPORT",
		MaxBody:     8 << 20,
		LoginPaths:  "/login,/index.php/login,/ocs/v2.php/core/getapppassword",
		LoginRPS:    3,
		LoginBurst:  5,
		AdminPaths:  "/settings,/index.php/settings,/ocs/v2.php/cloud/users,/apps",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440,921110",
		Notes: []string{
			"Uploads larger than 8 MiB are refused because the body is buffered for inspection; raise the limit or route large uploads through a streaming port.",
			"File downloads are not capped.",
		},
	},
	{
		ID:          "jellyfin",
		Name:        "Jellyfin",
		Description: "Media server API and dashboard; video streams must not be cut.",
		Methods:     "GET,HEAD,POST,PUT,DELETE,OPTIONS",
		MaxBody:     1 << 20,
		LoginPaths:  "/Users/AuthenticateByName,/users/authenticatebyname",
		LoginRPS:    3,
		LoginBurst:  5,
		AdminPaths:  "/System,/Users,/ScheduledTasks,/Library",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440",
		Notes: []string{
			"Responses are not capped: transcoded video and audio are streamed.",
			"The dashboard is a single-page app, so its admin paths are API routes.",
		},
	},
	{
		ID:          "plex",
		Name:        "Plex Media Server",
		Description: "Media server; clients authenticate against /users/sign_in.",
		Methods:     "GET,HEAD,POST,PUT,DELETE,OPTIONS",
		MaxBody:     1 << 20,
		LoginPaths:  "/users/sign_in,/api/v2/users/signin",
		LoginRPS:    3,
		LoginBurst:  5,
		AdminPaths:  "/web,/system,/manage",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440",
		Notes: []string{
			"Responses are not capped: media is streamed.",
		},
	},
	{
		ID:          "homeassistant",
		Name:        "Home Assistant",
		Description: "Automation UI and API, including the WebSocket the frontend holds open.",
		Methods:     "GET,HEAD,POST,DELETE,OPTIONS",
		MaxBody:     1 << 20,
		MaxResponse: 32 << 20,
		LoginPaths:  "/auth/login_flow,/auth/token",
		LoginRPS:    3,
		LoginBurst:  5,
		AdminPaths:  "/config,/developer-tools,/hassio,/api/config",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440",
		Notes: []string{
			"PATCH and PUT are refused; Home Assistant's API uses POST.",
			"The response ceiling is generous but finite: history and logbook downloads are capped at 32 MiB.",
		},
	},
	{
		ID:          "proxmox",
		Name:        "Proxmox VE",
		Description: "Virtualisation host console and API, authenticated with a ticket.",
		Methods:     "GET,HEAD,POST,PUT,DELETE,OPTIONS",
		MaxBody:     1 << 20,
		MaxResponse: 64 << 20,
		LoginPaths:  "/api2/json/access/ticket",
		LoginRPS:    3,
		LoginBurst:  5,
		AdminPaths:  "/api2/json/access,/api2/extjs",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440,921110",
		Notes: []string{
			"The console is at /api2/extjs and is restricted to the admin allowlist by default — widen it only for addresses you trust.",
			"SPICE and VNC consoles use a separate port range and are not proxied here.",
		},
	},
	{
		ID:          "generic",
		Name:        "Generic web application",
		Description: "A conservative baseline for an application with no special needs.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     1 << 20,
		MaxResponse: 32 << 20,
		LoginPaths:  "/login,/signin,/api/login",
		LoginRPS:    5,
		LoginBurst:  10,
		AdminPaths:  "/admin",
		AdminIPs:    "",
		Exceptions:  "",
		Notes: []string{
			"The admin allowlist is empty, so the admin-path rule is inert until an operator fills it in.",
		},
	},
}

// All returns every preset in menu order.
func All() []Preset { return all }

// Get finds a preset by ID.
func Get(id string) (Preset, bool) {
	for _, p := range all {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}

// Profile builds the WAF profile a preset suggests for one hostname. The name
// carries the host so two sites of the same application do not collide, and it
// stays editable in the console like any other profile.
func (p Preset) Profile(hostname string) model.Profile {
	name := p.Name
	if hostname != "" {
		name += " (" + hostname + ")"
	}
	return model.Profile{
		Name:           name,
		Mode:           "block",
		Paranoia:       1,
		Anomaly:        5,
		AllowedMethods: p.Methods,
		MaxBody:        p.MaxBody,
		MaxResponse:    p.MaxResponse,
		Exceptions:     p.Exceptions,
		LoginPaths:     p.LoginPaths,
		LoginRPS:       p.LoginRPS,
		LoginBurst:     p.LoginBurst,
		AdminPaths:     p.AdminPaths,
		AdminIPs:       p.AdminIPs,
	}
}
