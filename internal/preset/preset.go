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
		ID:          "vaultwarden",
		Name:        "Vaultwarden",
		Description: "Bitwarden-compatible password vault; clients sync through /identity/connect/token.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     32 << 20,
		MaxResponse: 32 << 20,
		LoginPaths:  "/identity/connect/token",
		LoginRPS:    3,
		LoginBurst:  5,
		AdminPaths:  "/admin",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440",
		Notes: []string{
			"Every client refreshes through /identity/connect/token, so the login limit applies to sync as well; a large household behind one NAT can hit it.",
			"Attachments are buffered for inspection, so uploads above 32 MiB are refused.",
		},
	},
	{
		ID:          "gitea",
		Name:        "Gitea / Forgejo",
		Description: "Self-hosted Git with a web UI; clones over HTTPS stream and must not be cut.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     64 << 20,
		LoginPaths:  "/user/login",
		LoginRPS:    5,
		LoginBurst:  10,
		AdminPaths:  "/-/admin,/api/v1/admin",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440,921110",
		Notes: []string{
			"Responses are not capped, so cloning a large repository is never interrupted.",
			"SSH on port 22 is not proxied here; publish it separately if you use it.",
		},
	},
	{
		ID:          "paperless",
		Name:        "Paperless-ngx",
		Description: "Document archive with an upload API and an admin area.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     64 << 20,
		MaxResponse: 64 << 20,
		LoginPaths:  "/accounts/login/,/api/token/",
		LoginRPS:    5,
		LoginBurst:  10,
		AdminPaths:  "/admin,/api/admin",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440",
		Notes: []string{
			"Scanned PDFs are buffered for inspection, so a document above 64 MiB is refused rather than truncated.",
			"Consumers that post through the token API count against the login limit, not the general rate.",
		},
	},
	{
		ID:          "grafana",
		Name:        "Grafana",
		Description: "Dashboards and alerting; the live view holds a WebSocket open.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     8 << 20,
		MaxResponse: 32 << 20,
		LoginPaths:  "/login,/api/login",
		LoginRPS:    5,
		LoginBurst:  10,
		AdminPaths:  "/admin,/org,/api/admin",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440",
		Notes: []string{
			"The response ceiling only cuts oversized exports; dashboards stream normally.",
			"Server administration, plugin installation and org management stay on the private allowlist.",
		},
	},
	{
		ID:          "uptime-kuma",
		Name:        "Uptime Kuma",
		Description: "Uptime monitor with a live dashboard and an authenticated API.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     2 << 20,
		MaxResponse: 8 << 20,
		LoginPaths:  "/login,/api/auth/login",
		LoginRPS:    5,
		LoginBurst:  10,
		AdminPaths:  "/settings,/api/settings",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440",
		Notes: []string{
			"The dashboard keeps a WebSocket open; if it is closed the UI stops updating even though checks continue.",
			"Settings and notification integrations expose credentials and stay on the private allowlist.",
		},
	},
	{
		ID:          "mealie",
		Name:        "Mealie",
		Description: "Recipe manager with a JSON API and a small admin area.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     16 << 20,
		MaxResponse: 16 << 20,
		LoginPaths:  "/login,/api/auth/token",
		LoginRPS:    5,
		LoginBurst:  10,
		AdminPaths:  "/admin,/api/admin",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440",
		Notes: []string{
			"A full backup import is the largest request this app makes; 16 MiB covers it.",
			"Recipe scrapers fetch images into the app, not through this profile.",
		},
	},
	{
		ID:          "navidrome",
		Name:        "Navidrome",
		Description: "Music server with Subsonic-compatible clients; audio is streamed.",
		Methods:     "GET,HEAD,POST,PUT,DELETE,OPTIONS",
		MaxBody:     2 << 20,
		LoginPaths:  "/login,/auth/login",
		LoginRPS:    10,
		LoginBurst:  20,
		AdminPaths:  "",
		AdminIPs:    "",
		Exceptions:  "920350,920440",
		Notes: []string{
			"Responses are not capped: tracks are streamed to every player.",
			"PATCH is refused; the Subsonic API and the web client use GET and POST.",
		},
	},
	{
		ID:          "photoprism",
		Name:        "PhotoPrism",
		Description: "Photo library with upload, indexing and a settings area.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     64 << 20,
		LoginPaths:  "/library/login,/api/v1/session",
		LoginRPS:    3,
		LoginBurst:  5,
		AdminPaths:  "/library/settings,/api/v1/settings",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440,921110",
		Notes: []string{
			"Original photos and videos are buffered for inspection, so files above 64 MiB are refused.",
			"Downloads and thumbnails stream and are not capped.",
		},
	},
	{
		ID:          "syncthing",
		Name:        "Syncthing",
		Description: "File synchronisation; only the web GUI is proxied, not the sync protocol.",
		Methods:     "GET,HEAD,POST,PUT,DELETE,OPTIONS",
		MaxBody:     2 << 20,
		MaxResponse: 8 << 20,
		AdminPaths:  "/rest,/settings",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440",
		Notes: []string{
			"The sync protocol uses port 22000 and is not proxied; exposing only the GUI keeps file transfer off the WAF.",
			"The GUI's /rest API is the whole administration surface, so it starts on the private allowlist.",
		},
	},
	{
		ID:          "n8n",
		Name:        "n8n",
		Description: "Workflow automation, including incoming webhooks and a live editor.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     32 << 20,
		MaxResponse: 32 << 20,
		LoginPaths:  "/rest/login,/signin",
		LoginRPS:    5,
		LoginBurst:  10,
		AdminPaths:  "/settings,/rest/settings,/rest/users",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440",
		Notes: []string{
			"Webhook payloads are buffered, so 32 MiB is the practical ceiling for an incoming call.",
			"The editor keeps a WebSocket open for execution output; user management stays private.",
		},
	},
	{
		ID:          "bookstack",
		Name:        "BookStack",
		Description: "Wiki with page revisions, image uploads and a settings area.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     32 << 20,
		MaxResponse: 32 << 20,
		LoginPaths:  "/login",
		LoginRPS:    5,
		LoginBurst:  10,
		AdminPaths:  "/settings",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440,921110",
		Notes: []string{
			"Exports and large attachments are the biggest responses; both fit under 32 MiB.",
			"The WYSIWYG editor posts Markdown and HTML, so 921110 is listed as a likely false positive to check in detect mode.",
		},
	},
	{
		ID:          "calcom",
		Name:        "Cal.com",
		Description: "Scheduling with public booking pages and an admin area.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     8 << 20,
		MaxResponse: 16 << 20,
		LoginPaths:  "/auth/login,/api/auth",
		LoginRPS:    5,
		LoginBurst:  10,
		AdminPaths:  "/settings/admin,/api/v1/admin",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440",
		Notes: []string{
			"Booking pages are public and POST without a login, so they are limited by the global rate only.",
			"Calendar and video integrations return secrets in the admin area, which stays private.",
		},
	},
	{
		ID:          "arr",
		Name:        "*arr suite (Sonarr, Radarr, Lidarr, Readarr, Prowlarr)",
		Description: "Media automation apps sharing one API shape and one settings area.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     8 << 20,
		MaxResponse: 32 << 20,
		LoginPaths:  "/login,/api/v3/login,/api/v1/login",
		LoginRPS:    5,
		LoginBurst:  10,
		AdminPaths:  "/settings,/system,/api/v3/config,/api/v1/config",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440",
		Notes: []string{
			"The API key travels in a header and grants full control, so the config and system routes stay on the private allowlist.",
			"Download clients and indexers call back from the LAN; the private ranges cover them.",
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
