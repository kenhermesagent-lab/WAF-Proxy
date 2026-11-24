// Package api exposes the authenticated admin API.
package api

//go:generate go run ../../tools/openapi -src server.go -version-file ../../VERSION -out ../../docs/openapi.yaml

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/acme"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/agentlink"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/anomaly"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/backup"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/bundle"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/canary"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/clientip"
	cf "github.com/kenhermesagent-lab/waf-proxy-docker/internal/cloudflared"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/config"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/crowdsec"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/intel"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/netmatch"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/notify"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/policy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/proxy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/rbac"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/siteres"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/streaming"
	updatepkg "github.com/kenhermesagent-lab/waf-proxy-docker/internal/updates"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/uptime"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/version"
)

const sessionCookie = "__wfp_sid"

type ctxKey int

const (
	sessionKey ctxKey = 1
	siteKey    ctxKey = 2
	// siteOverrideKey marks a request that asked for another site by header.
	siteOverrideKey ctxKey = 3
)

// Server is the admin API.
type Server struct {
	st      *store.Store
	box     *wfcrypto.Box
	cfg     *config.Config
	proxy   *proxy.Server
	policy  *policy.Engine
	bans    *ban.Engine
	feeds   *intel.Manager
	bundles *bundle.Manager
	certs   *acme.Manager
	// res holds one instance of policy, notify, anomaly, canary and ACME per
	// site. It is nil in tests and CLI paths, which set the single fields above.
	res         *siteres.Set
	cs          *crowdsec.Manager
	metrics     *metrics.Collector
	notify      *notify.Manager
	geo         *geoip.Geo
	log         *slog.Logger
	limiter     *auth.Limiter
	mux         *http.ServeMux
	started     time.Time
	streams     *streaming.Manager
	streamDrops func() int64
	backup      *backup.Manager
	anomaly     *anomaly.Manager
	canary      *canary.Monitor
	agentLinks  *agentlink.Dispatcher
	updates     *updatepkg.Manager
	uptime      *uptime.Manager
	restartFn   func()
	tailscale   TailscaleState
	cloudflared *cf.Supervisor

	// Cloudflare install progress and the last check result, both polled by the
	// page. cfNonce marks responses the connector delivered.
	cfMu      sync.Mutex
	cfRunning bool
	cfErr     string
	cfOutput  string
	cfChecks  []cloudflareCheck
	cfChecked string
	cfNonce   atomic.Value
	// Per-hostname results for the Apps tab, keyed by hostname.
	cfAppMu      sync.Mutex
	cfAppChecks  map[string][]cloudflareCheck
	cfAppChecked map[string]string

	// haStatus reports this node's effective role. Nil on a build or test
	// without HA, where the node is always standalone and serving.
	haStatus func() HAStatus
	// haWriteGate pauses configuration writes while a planned move quiesces
	// this node. Reads stay open. Nil means writes are never paused.
	haWriteGate func() bool
	// writes counts mutating console requests in flight, so a promotion
	// preflight can refuse to start while an edit is still landing.
	writes atomic.Int64
	// haOps runs the HA mutations; nil means the routes answer 409. haMu and
	// haLog keep the process-local action history the page shows.
	haOps HAOps
	// haChange starts or stops the HA loops after the switch is saved. It can
	// refuse, and the save is then rolled back. It reports whether the caller
	// must restart the process.
	haChange func(bool, string) (bool, error)
	haMu     sync.Mutex
	haLog    []HAEvent

	// CrowdSec one-click install progress, polled by the CrowdSec page.
	csMu      sync.Mutex
	csRunning bool
	csErr     string
	csOutput  string
	// Console enrolment state from `cscli console status`, cached briefly: the
	// page polls this endpoint every two seconds during an install.
	csConsoleRows map[string]string
	csConsoleAt   time.Time
	// csConsoleKey is the enrollment key pasted for the next install run.
	csConsoleKey string

	// Pending TOTP rotations are held server-side and keyed by session, so a
	// stolen session cannot confirm an authenticator of its own choosing.
	totpMu      sync.Mutex
	totpPending map[string]pendingTOTP

	// adminNets is the source allowlist for the console; nil means every
	// address may sign in. It is replaced atomically when settings change.
	adminNets atomic.Pointer[netmatch.Map[bool]]
}

type pendingTOTP struct {
	secret  string
	userID  int64
	expires time.Time
}

// New builds the API and registers every route.
func New(st *store.Store, box *wfcrypto.Box, cfg *config.Config, px *proxy.Server, pol *policy.Engine,
	bans *ban.Engine, feeds *intel.Manager, certs *acme.Manager, cs *crowdsec.Manager,
	met *metrics.Collector, nt *notify.Manager, geo *geoip.Geo, res *siteres.Set, log *slog.Logger) *Server {
	s := &Server{
		st: st, box: box, cfg: cfg, proxy: px, policy: pol, bans: bans, feeds: feeds,
		certs: certs, cs: cs, metrics: met, notify: nt, geo: geo, res: res, log: log,
		limiter: auth.NewLimiter(), mux: http.NewServeMux(), started: time.Now(),
		totpPending: map[string]pendingTOTP{},
	}
	// A backup covers the whole install, not just the default site.
	s.backup = backup.New(st.Unscoped(), box, log, s.backupDocument)
	if err := s.loadAdminAllowlist(); err != nil {
		log.Warn("admin allowlist not loaded", "err", err)
	}
	if kv, err := st.Settings(); err == nil {
		s.setCloudflareNonce(cf.Load(kv, box).Nonce)
	}
	s.routes()
	return s
}

// siteRes is the instance set of the site this request answers for. It is nil
// when the server was built with single instances (tests, CLI paths), and the
// single fields are used instead.
func (s *Server) siteRes(r *http.Request) *siteres.Bundle {
	if s.res == nil {
		return nil
	}
	b, err := s.res.For(s.db(r).SiteID())
	if err != nil {
		s.log.Error("per-site resources unavailable", "err", err)
		return nil
	}
	return b
}

// The five accessors below read the active site's instance, so a request on one
// site's console can never reach another site's policy, channels, anomaly
// thresholds, canary target or ACME account.

func (s *Server) policyFor(r *http.Request) *policy.Engine {
	if b := s.siteRes(r); b != nil {
		return b.Policy
	}
	return s.policy
}

func (s *Server) notifyFor(r *http.Request) *notify.Manager {
	if b := s.siteRes(r); b != nil {
		return b.Notify
	}
	return s.notify
}

func (s *Server) anomalyFor(r *http.Request) *anomaly.Manager {
	if b := s.siteRes(r); b != nil {
		return b.Anomaly
	}
	return s.anomaly
}

func (s *Server) canaryFor(r *http.Request) *canary.Monitor {
	if b := s.siteRes(r); b != nil {
		return b.Canary
	}
	return s.canary
}

func (s *Server) certsFor(r *http.Request) *acme.Manager {
	if b := s.siteRes(r); b != nil {
		return b.ACME
	}
	return s.certs
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /api/diagnostics", s.authed(s.diagnostics))
	m.HandleFunc("GET /api/diagnostics/bundle", s.authed(s.diagnosticsBundle))
	m.HandleFunc("POST /api/canary", s.authed(s.runCanary))
	m.HandleFunc("GET /api/health", s.health)
	m.HandleFunc("GET /api/ha/diagnostics", s.authed(s.haDiagnostics))
	m.HandleFunc("GET /api/ha", s.authed(s.haRoute))
	m.HandleFunc("GET /api/ha/events", s.authed(s.haEventsRoute))
	m.HandleFunc("PUT /api/ha/config", s.authed(s.haConfigRoute))
	m.HandleFunc("POST /api/ha/{action}", s.authed(s.haAction))
	m.HandleFunc("GET /api/version", s.versionInfo)
	m.HandleFunc("GET /api/setup/status", s.setupStatus)
	m.HandleFunc("POST /api/setup", s.setup)
	m.HandleFunc("POST /api/login", s.login)
	m.HandleFunc("GET /api/login/device", s.loginDevice)
	m.HandleFunc("GET /api/password/forgot", s.forgotAvailable)
	m.HandleFunc("POST /api/password/forgot", s.forgotPassword)
	m.HandleFunc("POST /api/password/reset", s.resetPassword)
	m.HandleFunc("GET /api/invite", s.inviteInfo)
	m.HandleFunc("POST /api/invite/accept", s.acceptInvite)

	m.HandleFunc("POST /api/logout", s.authed(s.logout))
	m.HandleFunc("POST /api/cache/purge", s.authed(s.purgeCache))
	m.HandleFunc("GET /api/me", s.authed(s.me))
	m.HandleFunc("GET /api/me/prefs", s.authed(s.mePrefs))
	m.HandleFunc("PUT /api/me/prefs", s.authed(s.mePrefs))
	m.HandleFunc("GET /api/sites", s.authed(s.listSites))
	m.HandleFunc("POST /api/sites", s.authed(s.createSite))
	m.HandleFunc("PUT /api/sites/{slug}", s.authed(s.updateSite))
	m.HandleFunc("DELETE /api/sites/{slug}", s.authed(s.deleteSite))
	m.HandleFunc("GET /api/sessions", s.authed(s.activeSessions))
	m.HandleFunc("GET /api/search", s.authed(s.globalSearch))
	m.HandleFunc("POST /api/account/password", s.authed(s.changePassword))
	m.HandleFunc("POST /api/account/email", s.authed(s.accountEmail))
	m.HandleFunc("GET /api/account/devices", s.authed(s.accountDevices))
	m.HandleFunc("DELETE /api/account/devices/{id}", s.authed(s.revokeAccountDevice))
	m.HandleFunc("POST /api/account/totp", s.authed(s.beginTOTP))
	m.HandleFunc("POST /api/account/totp/confirm", s.authed(s.confirmTOTP))
	m.HandleFunc("POST /api/account/logout-all", s.authed(s.logoutAll))

	m.HandleFunc("GET /api/users", s.authed(s.listUsers))
	m.HandleFunc("POST /api/users", s.authed(s.createUser))
	m.HandleFunc("POST /api/users/invite", s.authed(s.inviteUser))
	m.HandleFunc("PUT /api/users/{id}", s.authed(s.updateUser))
	m.HandleFunc("DELETE /api/users/{id}", s.authed(s.deleteUser))
	m.HandleFunc("GET /api/roles", s.authed(s.listRoles))
	m.HandleFunc("POST /api/roles", s.authed(s.createRole))
	m.HandleFunc("PUT /api/roles/{id}", s.authed(s.updateRole))
	m.HandleFunc("DELETE /api/roles/{id}", s.authed(s.deleteRole))

	m.HandleFunc("GET /api/updates/auto", s.authed(s.getAutoUpdate))
	m.HandleFunc("PUT /api/updates/auto", s.authed(s.putAutoUpdate))

	m.HandleFunc("GET /api/backup/schedule", s.authed(s.getBackup))
	m.HandleFunc("PUT /api/backup/schedule", s.authed(s.putBackup))
	m.HandleFunc("POST /api/backup/schedule/run", s.authed(s.runBackup))

	m.HandleFunc("GET /api/config/export.yaml", s.authed(s.exportConfigYAML))
	m.HandleFunc("POST /api/config/import.yaml", s.authed(s.importConfigYAML))
	m.HandleFunc("GET /api/settings", s.authed(s.getSettings))
	m.HandleFunc("PUT /api/settings", s.authed(s.putSettings))
	m.HandleFunc("GET /api/geoip", s.authed(s.getGeoIP))
	m.HandleFunc("POST /api/geoip/install", s.authed(s.installGeoIP))

	m.HandleFunc("GET /api/proxies", s.authed(s.listProxies))
	m.HandleFunc("POST /api/proxies", s.authed(s.createProxy))
	m.HandleFunc("PUT /api/proxies/{id}", s.authed(s.updateProxy))
	m.HandleFunc("DELETE /api/proxies/{id}", s.authed(s.deleteProxy))
	m.HandleFunc("POST /api/proxies/{id}/gate/revoke", s.authed(s.revokeGate))
	m.HandleFunc("GET /api/presets", s.authed(s.listPresets))
	m.HandleFunc("GET /api/profiles", s.authed(s.listProfiles))
	m.HandleFunc("POST /api/profiles", s.authed(s.createProfile))
	m.HandleFunc("PUT /api/profiles/{id}", s.authed(s.updateProfile))
	m.HandleFunc("DELETE /api/profiles/{id}", s.authed(s.deleteProfile))

	m.HandleFunc("GET /api/auth-providers", s.authed(s.listAuthProviders))
	m.HandleFunc("POST /api/auth-providers", s.authed(s.createAuthProvider))
	m.HandleFunc("PUT /api/auth-providers/{id}", s.authed(s.updateAuthProvider))
	m.HandleFunc("DELETE /api/auth-providers/{id}", s.authed(s.deleteAuthProvider))

	m.HandleFunc("GET /api/protection-profiles", s.authed(s.listProtectionProfiles))
	m.HandleFunc("GET /api/protection-profiles/audit", s.authed(s.auditProtectionHeaders))
	m.HandleFunc("POST /api/protection-profiles", s.authed(s.createProtectionProfile))
	m.HandleFunc("PUT /api/protection-profiles/{id}", s.authed(s.updateProtectionProfile))
	m.HandleFunc("DELETE /api/protection-profiles/{id}", s.authed(s.deleteProtectionProfile))
	m.HandleFunc("GET /api/access-profiles", s.authed(s.listAccessProfiles))
	m.HandleFunc("POST /api/access-profiles", s.authed(s.createAccessProfile))
	m.HandleFunc("PUT /api/access-profiles/{id}", s.authed(s.updateAccessProfile))
	m.HandleFunc("DELETE /api/access-profiles/{id}", s.authed(s.deleteAccessProfile))

	m.HandleFunc("GET /api/lists", s.authed(s.listAccessLists))
	m.HandleFunc("POST /api/lists", s.authed(s.createAccessList))
	m.HandleFunc("PUT /api/lists/{id}", s.authed(s.updateAccessList))
	m.HandleFunc("DELETE /api/lists/{id}", s.authed(s.deleteAccessList))

	m.HandleFunc("GET /api/policies", s.authed(s.listPolicies))
	m.HandleFunc("POST /api/policies", s.authed(s.createPolicy))
	m.HandleFunc("POST /api/policies/preflight", s.authed(s.preflightPolicy))
	m.HandleFunc("PUT /api/policies/{id}", s.authed(s.updatePolicy))
	m.HandleFunc("DELETE /api/policies/{id}", s.authed(s.deletePolicy))
	m.HandleFunc("GET /api/global-lists", s.authed(s.getGlobalLists))
	m.HandleFunc("PUT /api/global-lists", s.authed(s.putGlobalLists))
	m.HandleFunc("GET /api/asn-recommendations", s.authed(s.listASNRecommendations))

	m.HandleFunc("GET /api/bans", s.authed(s.listBans))
	m.HandleFunc("POST /api/bans", s.authed(s.createBan))
	m.HandleFunc("DELETE /api/bans/{id}", s.authed(s.deleteBan))
	m.HandleFunc("POST /api/bans/{id}/promote", s.authed(s.promoteBan))
	m.HandleFunc("POST /api/bans/bulk", s.authed(s.bulkBans))

	m.HandleFunc("POST /api/bans/rollup", s.authed(s.rollupBans))

	m.HandleFunc("GET /api/agents", s.authed(s.listAgentLinks))
	m.HandleFunc("POST /api/agents", s.authed(s.createAgentLink))
	m.HandleFunc("PUT /api/agents/{id}", s.authed(s.updateAgentLink))
	m.HandleFunc("DELETE /api/agents/{id}", s.authed(s.deleteAgentLink))
	m.HandleFunc("POST /api/agents/{id}/test", s.authed(s.testAgentLink))
	m.HandleFunc("POST /api/agents/{id}/retry", s.authed(s.retryAgentLink))
	m.HandleFunc("GET /api/agents/{id}/deliveries", s.authed(s.listAgentDeliveries))

	m.HandleFunc("GET /api/anomaly", s.authed(s.getAnomaly))
	m.HandleFunc("PUT /api/anomaly/settings", s.authed(s.putAnomalySettings))
	m.HandleFunc("POST /api/anomaly/events/{id}/ack", s.authed(s.acknowledgeAnomaly))

	m.HandleFunc("GET /api/intel/lookup", s.authed(s.lookupIP))

	m.HandleFunc("GET /api/feeds", s.authed(s.listFeeds))
	m.HandleFunc("POST /api/feeds", s.authed(s.createFeed))
	m.HandleFunc("POST /api/feeds/upload", s.authed(s.uploadFeed))
	m.HandleFunc("PUT /api/feeds/{id}", s.authed(s.updateFeed))
	m.HandleFunc("DELETE /api/feeds/{id}", s.authed(s.deleteFeed))
	m.HandleFunc("POST /api/feeds/{id}/refresh", s.authed(s.refreshFeed))

	m.HandleFunc("GET /api/bundles", s.authed(s.listBundles))
	m.HandleFunc("POST /api/bundles/check", s.authed(s.checkBundles))
	m.HandleFunc("POST /api/bundles/enable", s.authed(s.enableBundle))
	m.HandleFunc("PUT /api/bundles/providers", s.authed(s.saveBundleProvider))
	m.HandleFunc("DELETE /api/bundles/providers", s.authed(s.deleteBundleProvider))
	m.HandleFunc("GET /api/bundles/hits", s.authed(s.bundleHits))

	m.HandleFunc("GET /api/certs", s.authed(s.listCerts))
	m.HandleFunc("POST /api/certs", s.authed(s.createCert))
	m.HandleFunc("POST /api/certs/upload", s.authed(s.uploadCert))
	m.HandleFunc("POST /api/certs/internal", s.authed(s.issueInternalCert))
	m.HandleFunc("GET /api/certs/internal/root", s.authed(s.internalCARoot))
	m.HandleFunc("PUT /api/certs/{id}", s.authed(s.updateCert))
	m.HandleFunc("POST /api/certs/{id}/renew", s.authed(s.renewCert))
	m.HandleFunc("POST /api/certs/{id}/revoke", s.authed(s.revokeCert))
	m.HandleFunc("DELETE /api/certs/{id}", s.authed(s.deleteCert))

	m.HandleFunc("GET /api/metrics", s.authed(s.getMetrics))
	m.HandleFunc("GET /api/capacity", s.authed(s.getCapacity))
	m.HandleFunc("GET /metrics", s.prometheusMetrics)
	m.HandleFunc("GET /api/analytics", s.authed(s.getAnalytics))
	m.HandleFunc("GET /api/uptime", s.authed(s.getUptime))
	m.HandleFunc("GET /api/events", s.authed(s.listEvents))
	m.HandleFunc("GET /api/log-views", s.authed(s.listLogViews))
	m.HandleFunc("PUT /api/log-views/{name}", s.authed(s.saveLogView))
	m.HandleFunc("DELETE /api/log-views/{name}", s.authed(s.deleteLogView))
	m.HandleFunc("POST /api/simulate", s.authed(s.simulate))
	m.HandleFunc("GET /api/gate-failures", s.authed(s.listGateFailures))
	m.HandleFunc("GET /api/events/export.csv", s.authed(s.exportEventsCSV))
	m.HandleFunc("GET /api/events/incident.md", s.authed(s.logIncidentReportMarkdown))
	m.HandleFunc("GET /api/ips", s.authed(s.listIPs))
	m.HandleFunc("GET /api/ips/{ip}", s.authed(s.getIP))
	m.HandleFunc("GET /api/ips/{ip}/incident.md", s.authed(s.incidentReportMarkdown))
	m.HandleFunc("GET /api/crowdsec", s.authed(s.getCrowdSec))
	m.HandleFunc("PUT /api/crowdsec", s.authed(s.putCrowdSec))
	m.HandleFunc("POST /api/crowdsec/test", s.authed(s.testCrowdSec))
	m.HandleFunc("GET /api/crowdsec/status", s.authed(s.crowdsecStatus))
	m.HandleFunc("GET /api/crowdsec/install", s.authed(s.getCrowdSecInstall))
	m.HandleFunc("GET /api/crowdsec/blocklists", s.authed(s.getCrowdSecBlocklists))
	m.HandleFunc("POST /api/crowdsec/install", s.authed(s.startCrowdSecInstall))
	m.HandleFunc("POST /api/crowdsec/console", s.authed(s.enrollCrowdSecConsole))
	m.HandleFunc("POST /api/crowdsec/restart", s.authed(s.restartCrowdSec))
	m.HandleFunc("GET /api/globe", s.authed(s.getGlobe))
	m.HandleFunc("GET /api/globe/hits", s.authed(s.getGlobeHits))
	m.HandleFunc("GET /api/audit", s.authed(s.listAudit))
	m.HandleFunc("GET /api/audit/verify", s.authed(s.verifyAudit))
	m.HandleFunc("GET /api/audit/{id}", s.authed(s.getAuditEntry))
	m.HandleFunc("POST /api/audit/{id}/rollback", s.authed(s.rollbackAudit))

	m.HandleFunc("GET /api/notifications", s.authed(s.getNotifications))
	m.HandleFunc("PUT /api/notifications", s.authed(s.putNotifications))
	m.HandleFunc("POST /api/notifications/test", s.authed(s.testNotification))

	m.HandleFunc("GET /api/gate-users", s.authed(s.listGateUsers))
	m.HandleFunc("POST /api/gate-users", s.authed(s.createGateUser))
	m.HandleFunc("PUT /api/gate-users/{id}", s.authed(s.updateGateUser))
	m.HandleFunc("DELETE /api/gate-users/{id}", s.authed(s.deleteGateUser))

	m.HandleFunc("GET /api/backup", s.authed(s.exportBackup))
	m.HandleFunc("POST /api/backup/restore", s.authed(s.restoreBackup))
	m.HandleFunc("GET /api/stream", s.authed(s.stream))

	m.HandleFunc("GET /api/streaming", s.authed(s.getStreaming))
	m.HandleFunc("PUT /api/streaming/{id}", s.authed(s.putStreaming))
	m.HandleFunc("POST /api/system/restart", s.authed(s.restartProcess))
	m.HandleFunc("GET /api/tailscale", s.authed(s.getTailscale))
	m.HandleFunc("PUT /api/tailscale", s.authed(s.putTailscale))

	m.HandleFunc("GET /api/cloudflare", s.authed(s.getCloudflare))
	m.HandleFunc("PUT /api/cloudflare", s.authed(s.putCloudflare))
	m.HandleFunc("GET /api/cloudflare/install", s.authed(s.getCloudflareInstall))
	m.HandleFunc("POST /api/cloudflare/install", s.authed(s.startCloudflareInstall))
	m.HandleFunc("POST /api/cloudflare/connector", s.authed(s.cloudflareConnector))
	m.HandleFunc("POST /api/cloudflare/check", s.authed(s.cloudflareCheck))
	m.HandleFunc("GET /api/cloudflare/apps", s.authed(s.getCloudflareApps))
	m.HandleFunc("PUT /api/cloudflare/apps", s.authed(s.putCloudflareApps))
	m.HandleFunc("POST /api/cloudflare/apps/check", s.authed(s.checkCloudflareApps))

	m.HandleFunc("GET /api/updates", s.authed(s.getUpdates))
	m.HandleFunc("POST /api/updates/check", s.authed(s.checkUpdates))
	m.HandleFunc("POST /api/updates/apply", s.authed(s.applyUpdate))
	m.HandleFunc("GET /api/updates/app", s.authed(s.getAppUpdateStatus))
	m.HandleFunc("POST /api/updates/app", s.authed(s.applyAppUpdate))
	m.HandleFunc("POST /api/updates/app/config", s.authed(s.configureAppUpdate))

	m.HandleFunc("GET /api/mcp", s.authed(s.getMCP))
	m.HandleFunc("GET /api/mcp/tokens", s.authed(s.getMCP))
	m.HandleFunc("POST /api/mcp/tokens", s.authed(s.createMCPToken))
	m.HandleFunc("DELETE /api/mcp/tokens/{id}", s.authed(s.revokeMCPToken))
}

// SetStreaming attaches the media forwarder manager. A nil manager keeps the
// page readable and disables the controls that would change it.
func (s *Server) SetStreaming(m *streaming.Manager) { s.streams = m }

// SetStreamEventDrops attaches the relay event writer's drop counter, so a full
// queue shows on the scrape instead of only being counted in the process.
func (s *Server) SetStreamEventDrops(fn func() int64) { s.streamDrops = fn }

// SetUpdates attaches the host package inventory and the root-helper client.
func (s *Server) SetUpdates(m *updatepkg.Manager) { s.updates = m }

// SetUptime attaches the backend availability monitor.
func (s *Server) SetUptime(m *uptime.Manager) { s.uptime = m }

// SetRestart installs the callback used by POST /api/system/restart.
func (s *Server) SetRestart(fn func()) { s.restartFn = fn }

// Start prunes expired login-limit buckets.
func (s *Server) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.limiter.Cleanup()
			}
		}
	}()
}

// Handler wraps the mux with security headers and the site its Host names.
func (s *Server) Handler() http.Handler {
	return SecurityHeaders(s.withSite(s.mux))
}

// withSite binds the request to the site its Host belongs to. A host nobody
// claims, and every host on a single-site install, lands on the default site,
// so a console reached the way it always was behaves the same way.
func (s *Server) withSite(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := s.st.SiteForHost(r.Host)
		ctx := context.WithValue(r.Context(), siteKey, id)
		// The console's site switcher asks for another site by slug, and only
		// the host console may ask: a tenant host must not be able to retarget
		// even an unauthenticated route such as login with this header.
		if slug := strings.TrimSpace(r.Header.Get("X-WAF-Site")); slug != "" && id == s.st.SiteID() {
			if site, err := s.st.SiteBySlug(slug); err == nil && site.Enabled {
				ctx = context.WithValue(ctx, siteKey, site.ID)
				ctx = context.WithValue(ctx, siteOverrideKey, true)
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// consoleSite is the site whose console this request arrived on, which is the
// site the session was issued for regardless of any switch request.
func (s *Server) consoleSite(r *http.Request) int64 {
	id := s.st.SiteForHost(r.Host)
	if id == 0 {
		return s.st.SiteID()
	}
	return id
}

// storeFor is the handle a given site id reads through.
func (s *Server) storeFor(siteID int64) *store.Store {
	if siteID == 0 || siteID == s.st.SiteID() {
		return s.st
	}
	return s.st.InSite(siteID)
}

// db is the only store a handler may touch: it is bound to the site of the
// host the request arrived on. Outside the site middleware (background jobs,
// tests, the host-wide allowlist) it is the default site's handle.
func (s *Server) db(r *http.Request) *store.Store {
	if r == nil {
		return s.st
	}
	id, _ := r.Context().Value(siteKey).(int64)
	if id == 0 || id == s.st.SiteID() {
		return s.st
	}
	return s.st.InSite(id)
}

// reloadPolicies recompiles every site's policy after a write. Each engine
// reads only its own site's rows, so the cost is one reload per site and one
// site's edit can never leave another site's engine stale.
func (s *Server) reloadPolicies() {
	if s.res != nil {
		s.res.Each(func(b *siteres.Bundle) {
			if err := b.Policy.Reload(); err != nil {
				s.log.Error("reload site policies", "site", b.Site.Slug, "err", err)
			}
		})
		return
	}
	if s.policy != nil {
		if err := s.policy.Reload(); err != nil {
			s.log.Error("reload policies", "err", err)
		}
	}
}

// hostSettings is the default site's view, which the process-wide knobs
// (body cap, stealth, interfaces) come from.
func (s *Server) hostSettings() policy.Settings {
	if s.res != nil {
		if b := s.res.Default(); b != nil {
			return b.Policy.CurrentSettings()
		}
	}
	if s.policy != nil {
		return s.policy.CurrentSettings()
	}
	return policy.Settings{}
}

// reloadEngines recompiles the policy and proxy tables after a write. A server
// built without those engines (CLI paths and tests) skips the reload.
func (s *Server) reloadEngines(ctx context.Context) {
	s.reloadPolicies()
	if s.proxy != nil {
		if err := s.proxy.Reload(ctx); err != nil {
			s.log.Error("reload after write", "err", err)
		}
	}
}

// SecurityHeaders applies the admin UI hardening headers. It is exported so the
// static SPA handler, which is mounted outside the API mux, gets them too.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// authed enforces a session and, for mutating requests, a CSRF token.
func (s *Server) authed(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value == "" {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if !s.adminAddressAllowed(clientIP(r)) {
			writeError(w, http.StatusForbidden, "this address is not allowed to use the admin console")
			return
		}
		home := s.storeFor(s.consoleSite(r))
		sess, err := home.LookupSession(c.Value)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "session expired")
			return
		}
		if !s.authorize(sess, r) {
			writeError(w, http.StatusForbidden, "your role does not allow this action")
			return
		}
		// A standby serves reads and nothing else. Checking here covers every
		// route at once, including ones added later, instead of trusting each
		// handler to remember.
		if s.haStatus != nil {
			if ha := s.haStatusOf(); ha.Enabled && !ha.Serving && !standbyAllows(r.Method, r.URL.Path) {
				writeError(w, http.StatusConflict, "standby is read-only")
				return
			}
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if s.haWriteGate != nil && s.haWriteGate() {
				writeError(w, http.StatusConflict, "configuration writes are paused for a failover")
				return
			}
			s.writes.Add(1)
			defer s.writes.Add(-1)
		}
		// Sliding idle timeout (12 h) bounded by an absolute 7 day lifetime. It
		// only refreshes once less than half the window remains, so an active
		// session costs at most one write per six hours.
		idle := 12 * time.Hour
		if time.Until(sess.ExpiresAt) < idle/2 {
			next := time.Now().Add(idle)
			if abs := sess.CreatedAt.Add(7 * 24 * time.Hour); next.After(abs) {
				next = abs
			}
			if next.After(sess.ExpiresAt) {
				if err := home.TouchSession(sess.ID, next); err == nil {
					sess.ExpiresAt = next
				}
			}
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.CSRF)) != 1 {
				writeError(w, http.StatusForbidden, "invalid csrf token")
				return
			}
		}
		ctx := context.WithValue(r.Context(), sessionKey, sess)
		// The switcher belongs to the host console. A tenant session cannot use
		// it even when its role carries the wildcard permission, because the
		// site it asks for would otherwise become this request's store.
		if requested, _ := r.Context().Value(siteOverrideKey).(bool); requested &&
			(s.consoleSite(r) != s.st.SiteID() || !sess.Can(rbac.Permission("sites", "read"))) {
			ctx = context.WithValue(ctx, siteKey, s.consoleSite(r))
			ctx = context.WithValue(ctx, siteOverrideKey, false)
		}
		fn(w, r.WithContext(ctx))
	}
}

func sessionFrom(r *http.Request) *store.Session {
	sess, _ := r.Context().Value(sessionKey).(*store.Session)
	return sess
}

// trustedProxies is the process-wide allowlist whose X-Forwarded-For may name
// the client. Nil or empty means the socket peer always wins.
var trustedProxies *clientip.Resolver

// SetTrustedProxies installs the allowlist parsed from WAFPROXY_TRUSTED_PROXIES.
func SetTrustedProxies(r *clientip.Resolver) { trustedProxies = r }

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if trustedProxies == nil {
		return host
	}
	addr, ok := trustedProxies.FromRequest(r)
	if !ok {
		return host
	}
	return addr.String()
}

// ---------- public endpoints ----------

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	// The tunnel check compares this marker with the nonce it saved, so a cached
	// or unrelated response cannot pass as this console. Only the connector's
	// loopback peer gets it, so a direct visitor cannot read the marker.
	if nonce, _ := s.cfNonce.Load().(string); nonce != "" && loopbackPeer(r) {
		w.Header().Set("X-WAF-Origin", nonce)
	}
	ready := s.proxy == nil || s.proxy.Ready()
	body := map[string]any{
		"status": "ok", "version": version.Version, "uptime_s": int(time.Since(s.started).Seconds()),
	}
	if s.haStatus != nil {
		ha := s.haStatusOf()
		if ha.Enabled {
			ready = ready && ha.Serving
		}
		body["ha"] = ha
	}
	body["ready"] = ready
	status := http.StatusOK
	if r.URL.Query().Get("ready") == "1" && !ready {
		status = http.StatusServiceUnavailable
	}
	if m := s.canaryFor(r); m != nil {
		body["canary"] = m.Snapshot()
	}
	writeJSON(w, status, body)
}

// loopbackPeer reports whether the request arrived through a local connector
// rather than from the network.
func loopbackPeer(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && addr.IsLoopback()
}

// SetCanary attaches the scheduled probe whose last result health reports.
func (s *Server) SetCanary(m *canary.Monitor) { s.canary = m }

// HAStatus is the node's effective role, read fresh on each request so a
// transition is visible without a restart. Enabled is the stored setting;
// Serving is false on a standby.
type HAStatus struct {
	Enabled   bool   `json:"enabled"`
	Paired    bool   `json:"paired"`
	Role      string `json:"role"`
	State     string `json:"state"`
	Serving   bool   `json:"serving"`
	Epoch     int64  `json:"epoch"`
	Peer      string `json:"peer,omitempty"`
	Reason    string `json:"reason,omitempty"`
	ClusterID string `json:"cluster_id,omitempty"`
	// PeerFingerprint keys the acknowledgement the peer sent for this node's
	// stream.
	PeerFingerprint string `json:"peer_fingerprint,omitempty"`
	// UpdatedAt is when the role file last changed, so the page can show how
	// long this node has been in its current role.
	UpdatedAt string `json:"updated_at,omitempty"`
	// RuntimeError explains why the HA loops are not running even though the
	// stored switch is on. Without it the console only showed the role file.
	RuntimeError string `json:"runtime_error,omitempty"`
}

// SetHAStatus installs the role source used by health and the standby guard.
func (s *Server) SetHAStatus(fn func() HAStatus) { s.haStatus = fn }

// SetWriteGate installs the pause that stops new configuration writes while a
// move drains this node. Reads and the HA routes stay open.
func (s *Server) SetWriteGate(fn func() bool) { s.haWriteGate = fn }

// ConfigWritesInFlight reports mutating console requests still running. A
// promotion preflight uses it so a move does not start on top of an edit.
func (s *Server) ConfigWritesInFlight() int { return int(s.writes.Load()) }

// ReloadAll recompiles every site's policy and the proxy routing table from the
// database. A promotion calls it after draining replication, when this node's
// copy is at the peer's head.
func (s *Server) ReloadAll(ctx context.Context) error {
	s.reloadPolicies()
	if s.proxy != nil {
		if err := s.proxy.Reload(ctx); err != nil {
			return err
		}
	}
	return nil
}

// standbyAllows reports whether a request may reach its handler on a standby.
// Reads keep the console usable; the HA control routes and the login/account
// paths must stay reachable or nobody could operate the node.
func standbyAllows(method, path string) bool {
	if method == http.MethodGet || method == http.MethodHead {
		return true
	}
	for _, prefix := range []string{"/api/ha/", "/api/account/", "/api/login", "/api/logout", "/api/me"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// purgeCache drops the response cache for one host, or all hosts when the body
// names none. Operators reach for it after a backend redeploy.
func (s *Server) purgeCache(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Host string `json:"host"`
	}
	_ = decode(r, &in)
	removed := 0
	if s.proxy != nil {
		removed = s.proxy.PurgeCache(in.Host)
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "cache.purge", in.Host, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"removed": removed})
}

func (s *Server) versionInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"version": version.Version, "commit": version.Commit, "build_date": version.BuildDate,
	})
}

func (s *Server) setupStatus(w http.ResponseWriter, r *http.Request) {
	// First-boot setup creates the host administrator and writes host-wide
	// settings, so a tenant console never offers it.
	if s.consoleSite(r) != s.st.SiteID() {
		writeJSON(w, http.StatusOK, map[string]any{"needs_setup": false, "version": version.Version})
		return
	}
	n, err := s.db(r).CountUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if n > 0 {
		// Everything below describes the first-boot wizard, and this endpoint
		// is unauthenticated: once setup is done, report only what a signed-out
		// console needs to decide between the login form and the wizard.
		writeJSON(w, http.StatusOK, map[string]any{"needs_setup": false, "version": version.Version})
		return
	}
	wanIP, wanPort := listenerParts(s.cfg.ListenWAN, 443)
	lanIP, guiPort := listenerParts(s.cfg.ListenGUI, 8443)
	writeJSON(w, http.StatusOK, map[string]any{
		"needs_setup": true,
		"version":     version.Version,
		"geoip":       s.geo.Available(),
		"kernel":      kernelStatus(s.bans),
		// The native installer supplies real first-boot addresses. Prefilling
		// the wizard with them prevents it from silently rebinding the GUI to a
		// different address after the installer chose the LAN interface.
		"wan_ip":    wanIP,
		"wan_port":  wanPort,
		"lan_ip":    lanIP,
		"gui_port":  guiPort,
		"wan_iface": s.cfg.WANIface,
		"lan_iface": s.cfg.LANIface,
	})
}

func kernelStatus(b *ban.Engine) map[string]any {
	active, reason := b.KernelStatus()
	return map[string]any{"active": active, "reason": reason}
}

// listenerParts splits a listen address for the setup form. An unspecified or
// malformed host is returned empty so the wizard does not save "0.0.0.0" as a
// concrete address.
func listenerParts(addr string, fallbackPort int) (string, int) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fallbackPort
	}
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		return "", fallbackPort
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		n = fallbackPort
	}
	return host, n
}

type setupRequest struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	BaseDomain   string `json:"base_domain"`
	WANIP        string `json:"wan_ip"`
	WANPort      int    `json:"wan_port"`
	LANIP        string `json:"lan_ip"`
	GUIPort      int    `json:"gui_port"`
	DuckDNSToken string `json:"duckdns_token"`
	Email        string `json:"email"`
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	if s.consoleSite(r) != s.st.SiteID() {
		writeError(w, http.StatusForbidden, "setup runs on the host console")
		return
	}
	n, err := s.db(r).CountUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if n > 0 {
		writeError(w, http.StatusConflict, "setup already completed")
		return
	}
	var req setupRequest
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.BaseDomain = strings.ToLower(strings.TrimSpace(req.BaseDomain))
	if req.Username == "" || len(req.Password) < 12 || req.BaseDomain == "" {
		writeError(w, http.StatusBadRequest, "username, a 12+ character password and a base domain are required")
		return
	}
	if !validHostname(req.BaseDomain) {
		writeError(w, http.StatusBadRequest, "base domain is not a valid hostname")
		return
	}
	if req.WANPort == 0 {
		req.WANPort = 443
	}
	if req.GUIPort == 0 {
		req.GUIPort = 8443
	}
	// Both addresses are required: an empty bind address means "all
	// interfaces", which would put the admin GUI on the WAN.
	if net.ParseIP(strings.TrimSpace(req.WANIP)) == nil {
		writeError(w, http.StatusBadRequest, "WAN address must be an IP")
		return
	}
	if net.ParseIP(strings.TrimSpace(req.LANIP)) == nil {
		writeError(w, http.StatusBadRequest, "LAN address must be an IP")
		return
	}
	if req.WANPort < 1 || req.WANPort > 65535 || req.GUIPort < 1 || req.GUIPort > 65535 {
		writeError(w, http.StatusBadRequest, "ports must be between 1 and 65535")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot generate TOTP secret")
		return
	}
	codes, storedCodes, err := auth.NewRecoveryCodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot generate recovery codes")
		return
	}
	sealedSecret, err := s.box.Seal(secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encryption error")
		return
	}
	sealedCodes, err := s.box.Seal(storedCodes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encryption error")
		return
	}
	uid, err := s.db(r).CreateFirstUser(req.Username, hash, sealedSecret, sealedCodes, true)
	if err != nil {
		if errors.Is(err, store.ErrAlreadySetup) {
			writeError(w, http.StatusConflict, "setup already completed")
			return
		}
		writeError(w, http.StatusInternalServerError, "cannot create administrator")
		return
	}
	// The same address is the ACME account contact and where password-reset
	// links go; an account without one cannot use the email reset flow.
	if email := strings.TrimSpace(req.Email); email != "" {
		_ = s.db(r).SetUserEmail(uid, email)
	}

	settings := map[string]string{
		"base_domain":        req.BaseDomain,
		"wan_ip":             req.WANIP,
		"wan_port":           strconv.Itoa(req.WANPort),
		"lan_ip":             req.LANIP,
		"gui_port":           strconv.Itoa(req.GUIPort),
		"setup_complete":     "1",
		"retention_days":     "7",
		"dos_rps":            "100",
		"dos_burst":          "200",
		"asn_block":          "1",
		"stealth_drop":       "1",
		"stealth_ping":       "0",
		"protection_enabled": "1",
		"sample_above_rps":   "500",
		"max_body":           "131072",
		"gate_ttl_hours":     "12",
		"acme_email":         strings.TrimSpace(req.Email),
		"admin_allow_cidrs":  "",
		"bot_filter":         "off",
		"normalization_mode": "flag",
		"bot_filter_allow":   "Googlebot, Bingbot, DuckDuckBot, Applebot",
		"geoip_auto_update":  "1",
	}
	if s.cfg.WANIface != "" {
		settings["wan_iface"] = s.cfg.WANIface
	}
	if s.cfg.LANIface != "" {
		settings["lan_iface"] = s.cfg.LANIface
	}
	if err := s.db(r).SetSettings(settings); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot save settings")
		return
	}
	if req.DuckDNSToken != "" {
		creds, _ := json.Marshal(map[string]string{"token": req.DuckDNSToken})
		enc, err := s.box.Seal(string(creds))
		if err == nil {
			_ = s.db(r).UpsertDNSCredential("duckdns", "DuckDNS", enc)
		}
	}
	_ = s.policyFor(r).Reload()
	s.db(r).AddAudit(req.Username, "setup", "initial administrator created", clientIP(r))
	writeJSON(w, http.StatusCreated, map[string]any{
		"username":       req.Username,
		"otpauth_url":    auth.OTPAuthURL("WAF-Proxy", req.Username, secret),
		"totp_secret":    secret,
		"recovery_codes": codes,
		"base_domain":    req.BaseDomain,
	})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTP     string `json:"totp"`
	Recovery string `json:"recovery"`
	Remember bool   `json:"remember"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.adminAddressAllowed(ip) {
		writeError(w, http.StatusForbidden, "this address is not allowed to use the admin console")
		return
	}
	if !s.limiter.Allow("login:"+ip, 10, time.Minute) {
		writeError(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	var req loginRequest
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if !s.limiter.Allow("user:"+strings.ToLower(req.Username), 5, 15*time.Minute) {
		writeError(w, http.StatusTooManyRequests, "account temporarily locked")
		return
	}
	user, err := s.db(r).UserByUsername(req.Username)
	if err != nil || user == nil {
		// Spend the same argon2 work as a real account so response timing does
		// not reveal whether a username exists.
		auth.DummyVerify(req.Password)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if !auth.VerifyPassword(user.PasswordHash, req.Password) {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	recoveryUsed := false
	trusted := false
	if user.TOTPEnabled {
		// A remembered browser stands in for the code until its cookie expires.
		trusted = s.trustedDeviceUser(r, user.ID)
		ok := trusted
		if !ok {
			secret, derr := s.box.Open(user.TOTPSecret)
			if derr == nil {
				if step, valid := auth.ValidateTOTPStep(secret, req.TOTP, time.Now()); valid {
					// Spend the step: a code observed on the wire, or replayed from
					// a previous login, is rejected once it has been used.
					claimed, cerr := s.db(r).ClaimTOTPStep(user.ID, step)
					ok = cerr == nil && claimed
				}
			}
		}
		if !ok && req.Recovery != "" {
			ok = s.consumeRecoveryCode(r, user, req.Recovery)
			recoveryUsed = ok
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
	}
	token, err := wfcrypto.RandomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session error")
		return
	}
	csrf, err := wfcrypto.RandomToken(24)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session error")
		return
	}
	expires := time.Now().Add(12 * time.Hour)
	if err := s.db(r).CreateSession(token, user.ID, csrf, ip, r.UserAgent(), expires); err != nil {
		writeError(w, http.StatusInternalServerError, "session error")
		return
	}
	s.limiter.Reset("user:" + strings.ToLower(req.Username))
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, Expires: expires,
	})
	detail := ""
	if recoveryUsed {
		detail = "recovery code"
	}
	s.db(r).AddAudit(user.Username, "login", detail, ip)
	if req.Remember && user.TOTPEnabled && !trusted {
		s.rememberDevice(w, r, user.ID)
	}
	out := map[string]any{
		"username": user.Username, "csrf": csrf, "expires_at": expires.Format(time.RFC3339),
		"recovery_used": recoveryUsed,
	}
	// A recovery code means the authenticator is gone. Prepare a replacement
	// now, so the console can offer it before the operator leaves the page.
	if recoveryUsed {
		if secret, serr := auth.NewTOTPSecret(); serr == nil {
			s.totpMu.Lock()
			for id, p := range s.totpPending {
				if time.Now().After(p.expires) {
					delete(s.totpPending, id)
				}
			}
			s.totpPending[token] = pendingTOTP{secret: secret, userID: user.ID, expires: time.Now().Add(5 * time.Minute)}
			s.totpMu.Unlock()
			out["totp_secret"] = secret
			out["otpauth_url"] = auth.OTPAuthURL("WAF-Proxy", user.Username, secret)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if sess != nil {
		s.clearPendingTOTP(sess.ID)
		_ = s.db(r).DeleteSession(sess.ID)
		s.db(r).AddAudit(sess.Username, "logout", "", clientIP(r))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	kv, _ := s.db(r).Settings()
	user, _ := s.db(r).UserByID(sess.UserID)
	email := ""
	if user != nil {
		email = user.Email
	}
	site, _ := s.st.SiteByID(s.consoleSite(r))
	haOn := s.haStatusOf().Enabled
	canSwitch := s.consoleSite(r) == s.st.SiteID() && sess.Can(rbac.Permission("sites", "read"))
	body := map[string]any{
		"username": sess.Username, "csrf": sess.CSRF, "version": version.Version,
		"ha_enabled":  haOn,
		"base_domain": kv["base_domain"], "expires_at": sess.ExpiresAt,
		"totp_enabled": user != nil && user.TOTPEnabled,
		"email":        email,
		"role":         sess.Role, "permissions": sess.Permissions,
		"can_switch": canSwitch,
	}
	if haOn {
		body["ha_role"] = s.haStatusOf().Role
	}
	if site != nil {
		body["site"] = site.Slug
		body["site_name"] = site.Name
		body["site_host"] = site.ConsoleHost
	}
	if canSwitch {
		body["sites"] = s.switchable()
	}
	writeJSON(w, http.StatusOK, body)
}

// ---------- settings ----------

var publicSettingKeys = []string{
	"base_domain", "wan_ip", "wan_port", "lan_ip", "gui_port", "wan_iface", "lan_iface",
	"dos_rps", "dos_burst", "asn_block", "stealth_drop", "stealth_ping", "retention_days",
	"sample_above_rps", "max_body", "queue_ms", "body_timeout_s", "cache_pre_waf",
	"upstream_idle_conns",
	"protection_enabled", "acme_staging", "acme_email",
	"gate_ttl_hours", "home_lat", "home_lon", "decoy_hosts",
	"admin_allow_cidrs", "bot_filter", "bot_filter_allow", "geoip_auto_update",
	"normalization_mode", "ha_enabled",
}

// cacheFirstRefusal names why this site cannot answer a cache hit before the
// CRS: that path skips the access gate and every WAF request rule, so it is
// only offered where the gate is off and the site wants its traffic inspected.
func (s *Server) cacheFirstRefusal(st *store.Store) string {
	proxies, err := st.ListProxies()
	if err != nil {
		return "database error"
	}
	for _, p := range proxies {
		if p.GateMode != "" && p.GateMode != "off" {
			return "cache_pre_waf cannot be enabled on a site with an access gate"
		}
		if p.WAFMode != "block" && p.WAFMode != "detect" {
			return "cache_pre_waf needs the site's WAF mode to be block or detect"
		}
	}
	return ""
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	kv, err := s.db(r).Settings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	out := map[string]string{}
	for _, k := range publicSettingKeys {
		out[k] = kv[k]
	}
	// The console can answer for another site through the switcher, so the form
	// names the site this request is scoped to rather than the console's own.
	if site, err := s.st.SiteByID(s.db(r).SiteID()); err == nil && site != nil {
		out["site_slug"] = site.Slug
		out["site_name"] = site.Name
	}
	// A readable status ("active" or the reason), never Go's map syntax: the
	// GUI renders this straight into a badge.
	if active, reason := s.bans.KernelStatus(); active {
		out["kernel"] = "active"
	} else {
		out["kernel"] = reason
	}
	if s.geo != nil {
		out["geoip"] = fmt.Sprint(s.geo.Available())
	} else {
		out["geoip"] = "false"
	}
	// The settings form leaves the process-wide keys out of a non-default
	// site's save instead of submitting them and earning a refusal.
	out["host_wide_keys"] = strings.Join(store.HostSettingKeys(), ",")
	// Report the interfaces the collector is actually sampling, plus which of
	// them came from auto-detection rather than a configured field, so a fully
	// configured host still sees what its charts read.
	if s.metrics != nil {
		wan, lan := s.metrics.Detected()
		out["wan_iface_in_use"] = wan
		out["lan_iface_in_use"] = lan
		if strings.TrimSpace(kv["wan_iface"]) == "" {
			out["wan_iface_auto"] = "1"
		}
		if strings.TrimSpace(kv["lan_iface"]) == "" {
			out["lan_iface_auto"] = "1"
		}
		out["iface_available"] = strings.Join(metrics.Interfaces(), ", ")
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var in map[string]string
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	allowed := map[string]bool{}
	for _, k := range publicSettingKeys {
		allowed[k] = true
	}
	next := map[string]string{}
	for k, v := range in {
		if !allowed[k] {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "wan_ip", "lan_ip":
			// An empty bind address means all interfaces, which would expose
			// the GUI on the WAN; require an explicit address.
			if v == "" || net.ParseIP(v) == nil {
				writeError(w, http.StatusBadRequest, k+" must be an IP address")
				return
			}
		case "wan_port", "gui_port":
			if n, err := strconv.Atoi(v); v == "" || err != nil || n < 1 || n > 65535 {
				writeError(w, http.StatusBadRequest, k+" must be 1-65535")
				return
			}
		case "decoy_hosts":
			clean, msg := s.cleanDecoyHosts(r, v)
			if msg != "" {
				writeError(w, http.StatusBadRequest, msg)
				return
			}
			v = clean
		case "admin_allow_cidrs":
			clean, msg := validateAdminAllowlist(v, clientIP(r))
			if msg != "" {
				writeError(w, http.StatusBadRequest, msg)
				return
			}
			v = clean
		case "bot_filter":
			// An empty value is not a mode: it is how a settings row that was
			// never written reads back, and the engine already treats it as the
			// safe default. Accepting it lets a fresh site save the form.
			if v != "" && v != "off" && v != "scrapers" && v != "all" {
				writeError(w, http.StatusBadRequest, "bot_filter must be off, scrapers or all")
				return
			}
		case "normalization_mode":
			if v != "" && v != "off" && v != "flag" && v != "block" {
				writeError(w, http.StatusBadRequest, "normalization_mode must be off, flag or block")
				return
			}
		case "ha_enabled", "cache_pre_waf":
			// A switch that was never written reads back empty, and the form
			// posts every field it was served, so empty means "still unset"
			// rather than a mode. Refusing it blocked the whole form.
			if v == "" {
				continue
			}
			if v != "0" && v != "1" {
				writeError(w, http.StatusBadRequest, k+" must be 0 or 1")
				return
			}
			if k == "cache_pre_waf" && v == "1" {
				if msg := s.cacheFirstRefusal(s.db(r)); msg != "" {
					writeError(w, http.StatusBadRequest, msg)
					return
				}
			}
		}
		switch k {
		case "dos_rps", "dos_burst", "retention_days", "sample_above_rps", "max_body", "queue_ms", "body_timeout_s", "gate_ttl_hours", "upstream_idle_conns":
			if v == "" {
				break
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				writeError(w, http.StatusBadRequest, k+" must be numeric")
				return
			}
			switch k {
			case "retention_days":
				if n < 1 || n > 30 {
					writeError(w, http.StatusBadRequest, "retention_days must be 1-30")
					return
				}
			case "max_body":
				if n < 1024 || n > 8<<20 {
					writeError(w, http.StatusBadRequest, "max_body must be 1024-8388608 bytes")
					return
				}
			case "queue_ms":
				// 0 is a setting: shed at the door instead of waiting.
				if n < 0 || n > 5000 {
					writeError(w, http.StatusBadRequest, "queue_ms must be 0-5000")
					return
				}
			case "body_timeout_s":
				// 0 disables the deadline for large or genuinely slow uploads.
				if n < 0 || n > 3600 {
					writeError(w, http.StatusBadRequest, "body_timeout_s must be 0-3600")
					return
				}
			case "upstream_idle_conns":
				// One pool per upstream, and the pool is capped at its total.
				if n < 1 || n > 256 {
					writeError(w, http.StatusBadRequest, "upstream_idle_conns must be 1-256")
					return
				}
			case "gate_ttl_hours":
				if n < 1 || n > 720 {
					writeError(w, http.StatusBadRequest, "gate_ttl_hours must be 1-720")
					return
				}
			default:
				if n < 1 {
					writeError(w, http.StatusBadRequest, k+" must be positive")
					return
				}
			}
		}
		next[k] = v
	}
	previousHA, _ := s.st.GetSetting("ha_enabled")
	changedHA, haOn := false, false
	if v, ok := next["ha_enabled"]; ok && v != previousHA {
		changedHA, haOn = true, v == "1"
	}
	restartRequired := false
	// The HA guard runs before any row is written, so a refused switch leaves
	// the whole save untouched: no other key and no audit row changes. A tenant
	// console is not the host's decider, so it skips the guard and is refused
	// by SetSettings below.
	hostSave := s.db(r).SiteID() == s.st.SiteID()
	if changedHA && hostSave && s.haChange != nil {
		restart, err := s.haChange(haOn, strings.TrimSpace(r.Header.Get("X-HA-Cluster-ID")))
		if err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		restartRequired = restart
	}
	if err := s.db(r).SetSettings(next); err != nil {
		if changedHA && hostSave && s.haChange != nil {
			// The write failed after the loops moved, so put them back.
			if _, rerr := s.haChange(!haOn, ""); rerr != nil {
				s.log.Error("cannot undo the HA switch after a failed save", "err", rerr)
			}
		}
		if errors.Is(err, store.ErrHostWideSetting) {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "cannot save settings")
		return
	}
	if _, ok := next["admin_allow_cidrs"]; ok {
		if err := s.loadAdminAllowlist(); err != nil {
			s.log.Error("reload admin allowlist", "err", err)
		}
	}
	if s.policyFor(r) != nil {
		_ = s.policyFor(r).Reload()
		host := s.hostSettings()
		// A server built for a test or a CLI path has no listener to update.
		if s.proxy != nil {
			s.proxy.SetBodyLimit(host.MaxBody)
		}
		if s.bans != nil {
			s.bans.SetStealth(host.StealthPing, host.WANIface)
		}
		if s.metrics != nil {
			s.metrics.SetInterfaces(host.WANIface, host.LANIface)
		}
	}
	if s.proxy != nil {
		if err := s.proxy.Reload(r.Context()); err != nil {
			s.log.Error("reload after settings", "err", err)
		}
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "settings.update", strings.Join(keys(next), ","), clientIP(r))
	if changedHA {
		// This switch changes who can move the service address, so it gets its
		// own audit row rather than a phrase inside settings.update.
		action := "ha.enable"
		if !haOn {
			action = "ha.disable"
		}
		s.db(r).AddAudit(sess.Username, action, "", clientIP(r))
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "restart_required": restartRequired})
}

// cleanDecoyHosts normalizes a comma list and refuses entries that collide with
// a real proxy hostname, so saving the setting can never ban legitimate traffic.
func (s *Server) cleanDecoyHosts(r *http.Request, raw string) (string, string) {
	hosts := []string{}
	seen := map[string]bool{}
	proxies, _ := s.db(r).ListProxies()
	real := map[string]bool{}
	for _, p := range proxies {
		real[p.Hostname] = true
	}
	for _, part := range strings.Split(raw, ",") {
		host := policy.NormalizeHost(part)
		if host == "" {
			continue
		}
		if !policy.ValidDecoyHost(host) {
			return "", "invalid decoy hostname: " + part
		}
		if real[host] {
			return "", "decoy hostname is an active proxy: " + host
		}
		if !seen[host] {
			seen[host] = true
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)
	return strings.Join(hosts, ","), ""
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---------- helpers ----------

func decode(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 2<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

// decodeSent is decode plus the set of keys the caller actually sent, so a
// partial update can tell an omitted field from an explicit null.
func decodeSent(r *http.Request, v any) (map[string]json.RawMessage, error) {
	defer r.Body.Close()
	raw, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	sent := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &sent); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return nil, err
	}
	return sent, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func validHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 || strings.ContainsAny(h, " /:\\") {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return false
			}
		}
	}
	return true
}
