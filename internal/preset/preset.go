// Package preset holds starting configurations for applications that are
// commonly put behind the proxy. A preset is not a policy: it fills in a WAF
// profile so the operator edits a working starting point instead of a blank
// form, and it never enables anything the proxy cannot undo.
package preset

import (
	"sort"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

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
	// Gate is the access-gate mode this application deserves, or empty when it
	// has none. The drawer preselects it, and it stays editable: a gate only
	// covers browser sessions, so an app whose mobile client or API tokens must
	// reach it directly leaves this empty.
	Gate string `json:"gate"`
	// ProxyMaxBody suggests the site's buffered body ceiling; 0 leaves the host
	// default alone.
	ProxyMaxBody int64 `json:"proxy_max_body"`
	// BodySkipPaths suggests upload paths whose bodies stream to the app without
	// inspection, written as "METHOD /prefix". They are prefilled and editable,
	// never applied behind the operator's back.
	BodySkipPaths []string `json:"body_skip_paths"`
	// Steps is the ordered setup guide shown when the preset is chosen.
	Steps []string `json:"steps"`
	// Exceptions are OWASP CRS rule IDs commonly reported as false positives by
	// this application. They are suggestions: check them in detect mode first.
	Exceptions string   `json:"exceptions"`
	Notes      []string `json:"notes"`
	// Protection is the response hardening this application needs beyond the
	// baseline every site gets; a field is set only where the app needs more.
	Protection Protection `json:"protection"`
}

// Protection is the response-hardening a preset ships beside its WAF profile,
// so a site created from a preset starts with headers that fit the app instead
// of the generic set. The profile it builds is an ordinary, editable row.
type Protection struct {
	// PermissionsPolicy replaces the baseline feature list. An app that records
	// audio, video or the screen in the browser needs those features allowed for
	// its own origin; every other app denies them.
	PermissionsPolicy string `json:"permissions_policy"`
	// FrameOptions is "sameorigin", "deny" or "off" for X-Frame-Options.
	FrameOptions string `json:"frame_options"`
	// CSP replaces the baseline, which sends none. Only an app whose own
	// documentation publishes a policy gets one here.
	CSP string `json:"csp"`
	// ReferrerPolicy replaces the baseline.
	ReferrerPolicy string `json:"referrer_policy"`
}

// defaultPermissions denies what a browser app normally does not need, while
// leaving the page usable: an app that records audio or video overrides it.
const defaultPermissions = "camera=(), microphone=(), geolocation=()"

// privateRanges is the admin-path allowlist a preset starts from: the operator's
// own network. An admin path is refused for everyone else until it is edited.
const privateRanges = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1/32,::1/128"

var all = []Preset{
	{
		ID:           "nextcloud",
		Name:         "Nextcloud",
		Description:  "File sync and share over WebDAV, with an admin area under /settings.",
		Methods:      "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS,PROPFIND,PROPPATCH,MKCOL,COPY,MOVE,LOCK,UNLOCK,REPORT",
		MaxBody:      8 << 20,
		ProxyMaxBody: 64 << 20,
		BodySkipPaths: []string{
			"PUT /remote.php/dav/files/",
			"PUT /remote.php/webdav/",
		},
		Steps: []string{
			"Set the site body ceiling to 64 MiB (on the Protection tab, already prefilled) for the WebDAV API.",
			"The sync clients upload a whole file per PUT, so their two WebDAV roots are prefilled in Body-skip: those bodies stream without inspection.",
			"A streamed upload is not cut by the site's body deadline or its upstream timeout; a path left buffered still is, so raise them before removing that entry.",
			"Verify with a large upload: Events shows stage body-skip, status 200.",
		},
		LoginPaths: "/login,/index.php/login,/ocs/v2.php/core/getapppassword",
		LoginRPS:   3,
		LoginBurst: 5,
		AdminPaths: "/settings,/index.php/settings,/ocs/v2.php/cloud/users,/apps",
		AdminIPs:   privateRanges,
		Exceptions: "920350,920440,921110",
		// Nextcloud Talk records audio, video and the screen in the browser.
		Protection: Protection{
			PermissionsPolicy: "camera=(self), microphone=(self), display-capture=(self), geolocation=()",
		},
		Notes: []string{
			"The two WebDAV upload roots stream without inspection (Body-skip); any other path is buffered and capped by the site ceiling.",
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
		AdminPaths:  "/System,/ScheduledTasks,/Library",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440",
		Notes: []string{
			"Responses are not capped: transcoded video and audio are streamed.",
			"The dashboard is a single-page app, so its admin paths are API routes.",
			"User management is not path-restricted here because the login endpoint lives under the same /Users prefix; a remote login would be refused with it.",
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
		AdminPaths:  "/api2/extjs,/api2/json/access/users,/api2/json/access/roles,/api2/json/access/groups",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440,921110",
		Notes: []string{
			"The console is at /api2/extjs, and user, role and group management are on the admin allowlist by default — widen it only for addresses you trust.",
			"The ticket endpoint /api2/json/access/ticket is deliberately outside that list, so logging in from elsewhere is not refused by the admin-path rule.",
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
			"Subsonic clients send credentials on every /rest call, which a login limit cannot throttle without stalling playback: the global rate, the bot filter and the ban engine are what stand in front of them.",
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
		ID:            "immich",
		Name:          "Immich",
		Description:   "Photo and video library with a mobile app, chunked uploads and streamed playback.",
		Methods:       "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:       64 << 20,
		ProxyMaxBody:  256 << 20,
		BodySkipPaths: []string{"POST /api/assets"},
		Steps: []string{
			"Set the site body ceiling to 256 MiB (on the Protection tab, already prefilled); it covers ordinary photos and short clips on the JSON API.",
			"POST /api/assets is prefilled in Body-skip: the mobile app sends each photo or video as one non-resumable request, so whole-file uploads stream to Immich without being buffered or inspected.",
			"A streamed upload is not cut by the site's body deadline (30 s by default) or its upstream timeout, so a multi-GB clip needs nothing raised; a path left buffered still is cut.",
			"Method, path and header rules, bans, lists, rate limits and the access gate still apply to that path; only the body is unseen.",
			"Optional: name a trust list on the skip entry to exempt only your own networks.",
			"Verify with a large video: Events shows stage body-skip, status 200.",
		},
		LoginPaths: "/api/auth/login",
		LoginRPS:   3,
		LoginBurst: 5,
		AdminPaths: "/api/admin,/admin",
		AdminIPs:   privateRanges,
		Exceptions: "920350,920440",
		Notes: []string{
			"The mobile app and the CLI authenticate with an API key, which a gate would intercept: this preset leaves the gate off so backup and sync keep working.",
			"POST /api/assets streams to Immich, so a whole-file backup is not buffered or inspected; every other path is still buffered under the site ceiling.",
			"Photos and videos are streamed and not capped; the admin area stays on the private allowlist.",
		},
	},
	{
		ID:          "firefly",
		Name:        "Firefly III",
		Description: "Personal finance manager with a JSON API and CSV statement imports.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     32 << 20,
		MaxResponse: 32 << 20,
		LoginPaths:  "/login",
		LoginRPS:    3,
		LoginBurst:  5,
		Gate:        "accounts",
		Exceptions:  "920350,920440",
		Notes: []string{
			"Every balance, transaction and account sits behind one password, so the preset suggests an accounts gate in front of it.",
			"Scripts and bank importers use personal access tokens and cannot pass a gate; turn it off if this site serves them.",
			"A statement import is one buffered request, and 32 MiB covers several years of CSV.",
		},
	},
	{
		ID:          "audiobookshelf",
		Name:        "Audiobookshelf",
		Description: "Audiobook and podcast server; clients stream and sync over the same hostname.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     64 << 20,
		LoginPaths:  "/login,/api/login",
		LoginRPS:    5,
		LoginBurst:  10,
		AdminPaths:  "/settings,/api/settings",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440",
		Notes: []string{
			"The mobile apps sign in once and keep a token, so a gate would cut them off; the app's own accounts are the control here.",
			"Book uploads are buffered whole, so a file above 64 MiB is refused rather than partially written.",
			"Progress sync holds a WebSocket open and audio is streamed, so responses are not capped.",
		},
	},
	{
		ID:          "openwebui",
		Name:        "Open WebUI",
		Description: "Chat front end for local models; replies stream token by token.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     32 << 20,
		LoginPaths:  "/api/v1/auths/signin,/auth",
		LoginRPS:    3,
		LoginBurst:  5,
		AdminPaths:  "/admin,/api/v1/users,/api/v1/configs",
		AdminIPs:    privateRanges,
		Gate:        "accounts",
		Exceptions:  "920350,920440",
		// Voice input records from the microphone; nothing else is needed.
		Protection: Protection{PermissionsPolicy: "microphone=(self), camera=(), geolocation=()"},
		Notes: []string{
			"The admin area can add models, keys and tools that run on the host, so the preset suggests an accounts gate in front of the whole site.",
			"Replies are server-sent events: they are streamed, never buffered to a ceiling, or the answer would arrive all at once at the end.",
			"Attachments and RAG documents arrive whole; 32 MiB covers a large PDF.",
		},
	},
	{
		ID:          "containers",
		Name:        "Container managers (Portainer, Dockge, Komodo)",
		Description: "Web consoles that can start, stop and replace containers on the host.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     8 << 20,
		MaxResponse: 32 << 20,
		LoginPaths:  "/api/auth,/auth/login",
		LoginRPS:    3,
		LoginBurst:  5,
		AdminPaths:  "/api/endpoints,/api/stacks,/api/docker,/api/system,/api/users,/api/compose",
		AdminIPs:    privateRanges,
		Gate:        "accounts",
		Exceptions:  "920350,920440,921110",
		Notes: []string{
			"Whoever reaches this console can run any image on the host, so the preset suggests an accounts gate on top of the app's own login.",
			"Compose files are posted as JSON and land in one buffered body; 8 MiB is generous for a stack.",
			"The Docker socket is not proxied here. If a manager reaches a remote daemon, publish it separately and firewall it.",
		},
	},
	{
		ID:          "frigate",
		Name:        "Frigate",
		Description: "NVR with live camera views, recorded clips and a configuration editor.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     8 << 20,
		LoginPaths:  "/api/login,/login",
		LoginRPS:    3,
		LoginBurst:  5,
		AdminPaths:  "/api/config,/config",
		AdminIPs:    privateRanges,
		Gate:        "accounts",
		Exceptions:  "920350,920440",
		Notes: []string{
			"Camera feeds show who is home and the config editor can rewrite the detector and the broker, so the preset suggests an accounts gate.",
			"Live view and recorded clips are long responses and are not capped; the WebSocket for detections is the same stream.",
			"go2rtc and RTSP are separate ports and are not proxied here.",
		},
	},
	{
		ID:          "guacamole",
		Name:        "Apache Guacamole",
		Description: "Remote desktop gateway; the screen travels over a WebSocket tunnel.",
		Methods:     "GET,HEAD,POST,PUT,DELETE,OPTIONS",
		MaxBody:     2 << 20,
		LoginPaths:  "/api/tokens,/guacamole/api/tokens",
		LoginRPS:    3,
		LoginBurst:  5,
		AdminPaths:  "/api/session/data,/guacamole/api/session/data",
		AdminIPs:    privateRanges,
		Gate:        "accounts",
		Exceptions:  "920350,920440",
		Notes: []string{
			"This hostname is an authenticated tunnel to other machines: the preset suggests an accounts gate so a single leaked Guacamole password is not the only door.",
			"The display rides /websocket-tunnel, which must stay open and uncapped or the desktop freezes.",
			"RDP, VNC and SSH are dialled by Guacamole itself and are never exposed through this site.",
		},
	},
	{
		ID:          "actual",
		Name:        "Actual Budget",
		Description: "Envelope budgeting app that syncs a local budget file through the browser.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     32 << 20,
		MaxResponse: 64 << 20,
		LoginPaths:  "/account/login,/login",
		LoginRPS:    3,
		LoginBurst:  5,
		Gate:        "accounts",
		Exceptions:  "920350,920440",
		Notes: []string{
			"The whole household budget is one file behind one password, so the preset suggests an accounts gate in front of it.",
			"The sync protocol posts the whole change set on every save; 32 MiB of request and 64 MiB of response leave room for a large history.",
			"The client is the web app or its desktop wrapper, both of which hold the gate session like any browser.",
		},
	},
	{
		ID:          "bookmarks",
		Name:        "Read-later (Karakeep, Linkwarden)",
		Description: "Bookmark and archive managers that fetch pages and keep a private library.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     32 << 20,
		MaxResponse: 64 << 20,
		LoginPaths:  "/api/auth/callback/credentials,/api/auth/signin,/api/v1/auth/login,/api/v1/auth/signin",
		LoginRPS:    5,
		LoginBurst:  10,
		AdminPaths:  "/admin,/api/admin,/api/v1/users",
		AdminIPs:    privateRanges,
		Gate:        "accounts",
		Exceptions:  "920350,920440",
		Notes: []string{
			"The library is private by nature and the apps ship no second factor by default, so the preset suggests an accounts gate.",
			"The browser extensions post API tokens and cannot pass a gate: leave it off if you capture links that way, or capture through the web app.",
			"An archived page arrives as one buffered upload; 32 MiB is the ceiling for a saved snapshot.",
		},
	},
	{
		ID:          "rss",
		Name:        "Feed readers (FreshRSS, Miniflux)",
		Description: "RSS readers with a web UI and an API that phone apps poll.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     4 << 20,
		MaxResponse: 32 << 20,
		LoginPaths:  "/login,/v1/login,/_/auth",
		LoginRPS:    5,
		LoginBurst:  10,
		Exceptions:  "920350,920440",
		Notes: []string{
			"Phone apps poll /api or /v1 with a token, so a gate would stop them; this preset leaves it off and relies on the app's own accounts.",
			"The reader fetches other sites itself, on its own network, so a full-text refresh is not proxied here.",
			"FreshRSS administration is a query string on /i/, which a path rule cannot isolate; restrict the whole site if it must stay private.",
		},
	},
	{
		ID:          "wiki",
		Name:        "Wikis and notes (Outline, Wiki.js, Docmost, Memos)",
		Description: "Collaborative documentation with uploads, search and an editor.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     32 << 20,
		MaxResponse: 32 << 20,
		LoginPaths:  "/login,/api/auth/login,/api/v1/auth/signin,/api/auth/oidc",
		LoginRPS:    5,
		LoginBurst:  10,
		Exceptions:  "920350,920440,921110",
		Notes: []string{
			"No admin path is restricted: these apps are meant to be read and edited from anywhere, and their own roles decide who administers them.",
			"The editor posts Markdown and HTML, so 921110 is listed as a likely false positive to check in detect mode.",
			"Attachments and page exports fit under 32 MiB; a larger single upload should go to object storage instead.",
		},
	},
	{
		ID:            "filesync",
		Name:          "File sync (Seafile, ownCloud)",
		Description:   "Desktop and mobile clients that sync files, including WebDAV on ownCloud.",
		Methods:       "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS,PROPFIND,PROPPATCH,MKCOL,COPY,MOVE,LOCK,UNLOCK,REPORT",
		MaxBody:       16 << 20,
		ProxyMaxBody:  64 << 20,
		BodySkipPaths: []string{"POST /seafhttp/", "PUT /remote.php/dav/files/"},
		Steps: []string{
			"Set the site body ceiling to 64 MiB (on the Protection tab, already prefilled); both clients upload in chunks that fit that.",
			"Seafile's web UI posts every upload to /seafhttp/, and ownCloud's clients PUT whole files to /remote.php/dav/files/: both prefixes are prefilled in Body-skip, so those bodies stream to the app instead of being buffered and inspected.",
			"A skip entry with no trust lists exempts every source; one that names trust lists exempts only the sources on them, so any client outside those lists is inspected in full and must fit the body ceiling. Leave the lists empty unless you mean to exempt only your own networks.",
			"A streamed upload is not cut by the site's body deadline or upstream timeout; delete a skip entry and raise both if you would rather inspect those uploads.",
		},
		LoginPaths: "/api2/auth-token/,/index.php/login,/ocs/v2.php/core/getapppassword",
		LoginRPS:   3,
		LoginBurst: 5,
		AdminPaths: "/sys,/settings/admin",
		AdminIPs:   privateRanges,
		Exceptions: "920350,920440",
		Notes: []string{
			"Seafile's web login is a Django form: the browser's Origin must match, so add CSRF_TRUSTED_ORIGINS = [\"https://<hostname>\"] (scheme included) to seahub_settings.py, or on Seafile 12+ set SEAFILE_SERVER_PROTOCOL=https and SEAFILE_SERVER_HOSTNAME. A mismatch answers 403 CSRF verification failed, and so does an Origin of null, which any proxy sending Referrer-Policy: no-referrer forces onto the form post.",
			"920350 is excepted because a site reached by its IP address has a numeric Host, which CRS flags; with a hostname the rule never fires.",
			"920440 is excepted because a sync client can upload a file whose path ends in .dll, .bat, .ini or .asa, which CRS refuses by extension list; .exe and .shtml are not on that list.",
			"921110 needs no exception here: the proxy refuses two Content-Length headers, or a length beside a chunked body, before the WAF runs. An encoded CRLF in a path is still refused, by 921190 and the path-traversal rules.",
			"The sync clients authenticate with a token, so a gate would stop every device; the app's own accounts and its sharing rules are the control.",
			"Seafile's web uploads and ownCloud's whole-file PUTs stream through the prefilled skip entries; a chunked upload on any other path is buffered and must fit 16 MiB. Downloads stay uncapped.",
			"Server administration (/sys on Seafile, /settings/admin on ownCloud) stays on the private allowlist.",
		},
	},
	{
		ID:          "filebrowser",
		Name:        "File managers (FileBrowser, copyparty)",
		Description: "Browse, upload and share files on the host over a web UI and WebDAV.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS,PROPFIND,COPY,MOVE",
		MaxBody:     64 << 20,
		LoginPaths:  "/api/login,/login",
		LoginRPS:    3,
		LoginBurst:  5,
		AdminPaths:  "/settings,/api/settings",
		AdminIPs:    privateRanges,
		Gate:        "accounts",
		Exceptions:  "920350,920440,921110",
		Notes: []string{
			"A file manager exposes the whole shared tree, and copyparty's default is a single shared account, so the preset suggests an accounts gate.",
			"Uploads are buffered whole, so 64 MiB is the practical limit for a single file; downloads stream uncapped.",
			"Share links are meant to be public: a gate would put them behind the same login. Turn it off if the site publishes links.",
		},
	},
	{
		ID:          "stirling",
		Name:        "Stirling-PDF",
		Description: "PDF toolbox: merge, split, OCR and convert, with uploads of the source files.",
		Methods:     "GET,HEAD,POST,PUT,DELETE,OPTIONS",
		MaxBody:     64 << 20,
		MaxResponse: 64 << 20,
		LoginPaths:  "/api/v1/auth/login,/login",
		LoginRPS:    3,
		LoginBurst:  5,
		Gate:        "accounts",
		Exceptions:  "920350,920440",
		Notes: []string{
			"Stirling-PDF ships with logins disabled, so anyone who finds the hostname can process and download documents: the preset suggests an accounts gate.",
			"Uploaded and produced PDFs are both buffered; 64 MiB is the ceiling for a single document in either direction.",
			"Turn the gate off only for a deliberately public converter, and keep the global rate limit on.",
		},
	},
	{
		ID:          "matrix",
		Name:        "Matrix (Synapse, Conduit)",
		Description: "Matrix homeserver client API; every phone and desktop client talks to it directly.",
		Methods:     "GET,HEAD,POST,PUT,DELETE,OPTIONS",
		MaxBody:     64 << 20,
		LoginPaths:  "/_matrix/client/v3/login,/_matrix/client/r0/login",
		LoginRPS:    5,
		LoginBurst:  10,
		AdminPaths:  "/_synapse/admin",
		AdminIPs:    privateRanges,
		Exceptions:  "920350,920440",
		Notes: []string{
			"Clients sign in once and keep a token, so a gate would disconnect every device; the homeserver's own login and its admin API are the control.",
			"Media uploads are buffered whole and downloads stream uncapped; 64 MiB is the per-upload ceiling.",
			"Federation uses port 8448 and is not proxied here — open it separately if this homeserver federates.",
		},
	},
	{
		ID:          "dnsadmin",
		Name:        "DNS consoles (Pi-hole, AdGuard Home, Technitium)",
		Description: "DNS resolver dashboards and settings; one shared password guards the whole network.",
		Methods:     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		MaxBody:     1 << 20,
		MaxResponse: 16 << 20,
		LoginPaths:  "/admin/login.php,/api/auth,/login.html,/control/login,/api/user/login",
		LoginRPS:    3,
		LoginBurst:  5,
		AdminPaths:  "/admin/settings.php,/admin/api.php,/control/settings,/control/clients,/api/config,/api/settings",
		AdminIPs:    privateRanges,
		Gate:        "accounts",
		Exceptions:  "920350,920440",
		Notes: []string{
			"Reaching this console means controlling DNS for every device on the network, and the default is one shared password: the preset suggests an accounts gate.",
			"Any client that reads the API directly — a phone app or a dashboard — cannot pass a gate; turn it off if one does.",
			"DNS itself is port 53 and never proxied; only the console is on this hostname.",
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

// All returns every preset in menu order: alphabetical by the name the drawer
// shows, so the list is the same wherever it is drawn. A leading symbol is
// ignored when sorting, so "*arr suite" sits among the As instead of ahead of
// everything.
func All() []Preset {
	out := make([]Preset, len(all))
	copy(out, all)
	sort.SliceStable(out, func(i, j int) bool { return sortKey(out[i].Name) < sortKey(out[j].Name) })
	return out
}

func sortKey(name string) string {
	return strings.ToLower(strings.TrimLeft(strings.TrimSpace(name), "*_-#~ "))
}

// Get finds a preset by ID.
func Get(id string) (Preset, bool) {
	for _, p := range all {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}

// ProtectionProfile builds the response hardening a preset suggests for one
// hostname. The name carries the host for the same reason the WAF profile does,
// and the row stays editable in the console like any other.
func (p Preset) ProtectionProfile(hostname string) model.ProtectionProfile {
	name := p.Name + " hardening"
	if hostname != "" {
		name += " (" + hostname + ")"
	}
	over := func(v, baseline string) string {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
		return baseline
	}
	return model.ProtectionProfile{
		Name:              name,
		ForceHTTPS:        true,
		HSTS:              true,
		HSTSSubdomains:    true,
		NoSniff:           true,
		HideServer:        true,
		FrameOptions:      over(p.Protection.FrameOptions, "sameorigin"),
		ReferrerPolicy:    over(p.Protection.ReferrerPolicy, "strict-origin-when-cross-origin"),
		PermissionsPolicy: over(p.Protection.PermissionsPolicy, defaultPermissions),
		CSP:               strings.TrimSpace(p.Protection.CSP),
	}
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
