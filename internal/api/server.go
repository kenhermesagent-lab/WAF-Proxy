// Package api exposes the authenticated admin API.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/acme"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/config"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/crowdsec"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/intel"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/notify"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/plex"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/policy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/proxy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/version"
)

const sessionCookie = "__wfp_sid"

type ctxKey int

const sessionKey ctxKey = 1

// Server is the admin API.
type Server struct {
	st        *store.Store
	box       *wfcrypto.Box
	cfg       *config.Config
	proxy     *proxy.Server
	policy    *policy.Engine
	bans      *ban.Engine
	feeds     *intel.Manager
	certs     *acme.Manager
	cs        *crowdsec.Manager
	metrics   *metrics.Collector
	notify    *notify.Manager
	geo       *geoip.Geo
	log       *slog.Logger
	limiter   *auth.Limiter
	mux       *http.ServeMux
	started   time.Time
	plex      *plex.Manager
	restartFn func()

	// Pending TOTP rotations are held server-side and keyed by session, so a
	// stolen session cannot confirm an authenticator of its own choosing.
	totpMu      sync.Mutex
	totpPending map[string]pendingTOTP
}

type pendingTOTP struct {
	secret  string
	userID  int64
	expires time.Time
}

// New builds the API and registers every route.
func New(st *store.Store, box *wfcrypto.Box, cfg *config.Config, px *proxy.Server, pol *policy.Engine,
	bans *ban.Engine, feeds *intel.Manager, certs *acme.Manager, cs *crowdsec.Manager,
	met *metrics.Collector, nt *notify.Manager, geo *geoip.Geo, log *slog.Logger) *Server {
	s := &Server{
		st: st, box: box, cfg: cfg, proxy: px, policy: pol, bans: bans, feeds: feeds,
		certs: certs, cs: cs, metrics: met, notify: nt, geo: geo, log: log,
		limiter: auth.NewLimiter(), mux: http.NewServeMux(), started: time.Now(),
		totpPending: map[string]pendingTOTP{},
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /api/health", s.health)
	m.HandleFunc("GET /api/version", s.versionInfo)
	m.HandleFunc("GET /api/setup/status", s.setupStatus)
	m.HandleFunc("POST /api/setup", s.setup)
	m.HandleFunc("POST /api/login", s.login)

	m.HandleFunc("POST /api/logout", s.authed(s.logout))
	m.HandleFunc("GET /api/me", s.authed(s.me))
	m.HandleFunc("POST /api/account/password", s.authed(s.changePassword))
	m.HandleFunc("POST /api/account/totp", s.authed(s.beginTOTP))
	m.HandleFunc("POST /api/account/totp/confirm", s.authed(s.confirmTOTP))
	m.HandleFunc("POST /api/account/logout-all", s.authed(s.logoutAll))

	m.HandleFunc("GET /api/settings", s.authed(s.getSettings))
	m.HandleFunc("PUT /api/settings", s.authed(s.putSettings))

	m.HandleFunc("GET /api/proxies", s.authed(s.listProxies))
	m.HandleFunc("POST /api/proxies", s.authed(s.createProxy))
	m.HandleFunc("GET /api/proxies/{id}", s.authed(s.getProxy))
	m.HandleFunc("PUT /api/proxies/{id}", s.authed(s.updateProxy))
	m.HandleFunc("DELETE /api/proxies/{id}", s.authed(s.deleteProxy))
	m.HandleFunc("PUT /api/proxies/{id}/gate", s.authed(s.setGate))
	m.HandleFunc("POST /api/proxies/{id}/gate/revoke", s.authed(s.revokeGate))
	m.HandleFunc("GET /api/profiles", s.authed(s.listProfiles))
	m.HandleFunc("PUT /api/profiles/{id}", s.authed(s.updateProfile))

	m.HandleFunc("GET /api/policies", s.authed(s.listPolicies))
	m.HandleFunc("POST /api/policies", s.authed(s.createPolicy))
	m.HandleFunc("PUT /api/policies/{id}", s.authed(s.updatePolicy))
	m.HandleFunc("DELETE /api/policies/{id}", s.authed(s.deletePolicy))

	m.HandleFunc("GET /api/bans", s.authed(s.listBans))
	m.HandleFunc("POST /api/bans", s.authed(s.createBan))
	m.HandleFunc("DELETE /api/bans/{id}", s.authed(s.deleteBan))
	m.HandleFunc("POST /api/bans/{id}/promote", s.authed(s.promoteBan))

	m.HandleFunc("GET /api/feeds", s.authed(s.listFeeds))
	m.HandleFunc("POST /api/feeds", s.authed(s.createFeed))
	m.HandleFunc("PUT /api/feeds/{id}", s.authed(s.updateFeed))
	m.HandleFunc("DELETE /api/feeds/{id}", s.authed(s.deleteFeed))
	m.HandleFunc("POST /api/feeds/{id}/refresh", s.authed(s.refreshFeed))
	m.HandleFunc("GET /api/intel", s.authed(s.intelStatus))

	m.HandleFunc("GET /api/certs", s.authed(s.listCerts))
	m.HandleFunc("POST /api/certs", s.authed(s.createCert))
	m.HandleFunc("POST /api/certs/{id}/renew", s.authed(s.renewCert))
	m.HandleFunc("DELETE /api/certs/{id}", s.authed(s.deleteCert))
	m.HandleFunc("GET /api/dns/providers", s.authed(s.dnsProviders))
	m.HandleFunc("GET /api/dns/credentials", s.authed(s.listDNSCredentials))

	m.HandleFunc("GET /api/metrics", s.authed(s.getMetrics))
	m.HandleFunc("GET /api/events", s.authed(s.listEvents))
	m.HandleFunc("GET /api/events/export.csv", s.authed(s.exportEventsCSV))
	m.HandleFunc("GET /api/ips", s.authed(s.listIPs))
	m.HandleFunc("GET /api/ips/{ip}", s.authed(s.getIP))
	m.HandleFunc("GET /api/crowdsec/status", s.authed(s.crowdsecStatus))
	m.HandleFunc("GET /api/globe", s.authed(s.getGlobe))
	m.HandleFunc("GET /api/audit", s.authed(s.listAudit))

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

	m.HandleFunc("GET /api/plex", s.authed(s.getPlex))
	m.HandleFunc("PUT /api/plex", s.authed(s.putPlex))
	m.HandleFunc("POST /api/system/restart", s.authed(s.restartProcess))
}

// SetPlex attaches the Plex forwarder manager. A nil manager keeps the page
// readable and disables the controls that would change it.
func (s *Server) SetPlex(m *plex.Manager) { s.plex = m }

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

// Handler wraps the mux with security headers.
func (s *Server) Handler() http.Handler {
	return SecurityHeaders(s.mux)
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
		sess, err := s.st.LookupSession(c.Value)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "session expired")
			return
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
				if err := s.st.TouchSession(sess.ID, next); err == nil {
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
		fn(w, r.WithContext(ctx))
	}
}

func sessionFrom(r *http.Request) *store.Session {
	sess, _ := r.Context().Value(sessionKey).(*store.Session)
	return sess
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------- public endpoints ----------

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "version": version.Version, "uptime_s": int(time.Since(s.started).Seconds()),
	})
}

func (s *Server) versionInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"version": version.Version, "commit": version.Commit, "build_date": version.BuildDate,
	})
}

func (s *Server) setupStatus(w http.ResponseWriter, r *http.Request) {
	n, err := s.st.CountUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	base, _ := s.st.GetSetting("base_domain")
	writeJSON(w, http.StatusOK, map[string]any{
		"needs_setup": n == 0,
		"base_domain": base,
		"version":     version.Version,
		"geoip":       s.geo.Available(),
		"kernel":      kernelStatus(s.bans),
	})
}

func kernelStatus(b *ban.Engine) map[string]any {
	active, reason := b.KernelStatus()
	return map[string]any{"active": active, "reason": reason}
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
	n, err := s.st.CountUsers()
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
	if _, err := s.st.CreateFirstUser(req.Username, hash, sealedSecret, sealedCodes, true); err != nil {
		if errors.Is(err, store.ErrAlreadySetup) {
			writeError(w, http.StatusConflict, "setup already completed")
			return
		}
		writeError(w, http.StatusInternalServerError, "cannot create administrator")
		return
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
	}
	if err := s.st.SetSettings(settings); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot save settings")
		return
	}
	if req.DuckDNSToken != "" {
		creds, _ := json.Marshal(map[string]string{"token": req.DuckDNSToken})
		enc, err := s.box.Seal(string(creds))
		if err == nil {
			_ = s.st.UpsertDNSCredential("duckdns", "DuckDNS", enc)
		}
	}
	_ = s.policy.Reload()
	s.st.AddAudit(req.Username, "setup", "initial administrator created", clientIP(r))
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
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
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
	user, err := s.st.UserByUsername(req.Username)
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
	if user.TOTPEnabled {
		secret, derr := s.box.Open(user.TOTPSecret)
		ok := false
		if derr == nil {
			if step, valid := auth.ValidateTOTPStep(secret, req.TOTP, time.Now()); valid {
				// Spend the step: a code observed on the wire, or replayed from
				// a previous login, is rejected once it has been used.
				claimed, cerr := s.st.ClaimTOTPStep(user.ID, step)
				ok = cerr == nil && claimed
			}
		}
		if !ok && req.Recovery != "" {
			ok = s.consumeRecoveryCode(user, req.Recovery)
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
	if err := s.st.CreateSession(token, user.ID, csrf, ip, r.UserAgent(), expires); err != nil {
		writeError(w, http.StatusInternalServerError, "session error")
		return
	}
	s.limiter.Reset("user:" + strings.ToLower(req.Username))
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, Expires: expires,
	})
	s.st.AddAudit(user.Username, "login", "", ip)
	writeJSON(w, http.StatusOK, map[string]any{
		"username": user.Username, "csrf": csrf, "expires_at": expires.Format(time.RFC3339),
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if sess != nil {
		s.clearPendingTOTP(sess.ID)
		_ = s.st.DeleteSession(sess.ID)
		s.st.AddAudit(sess.Username, "logout", "", clientIP(r))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	kv, _ := s.st.Settings()
	user, _ := s.st.UserByID(sess.UserID)
	writeJSON(w, http.StatusOK, map[string]any{
		"username": sess.Username, "csrf": sess.CSRF, "version": version.Version,
		"base_domain": kv["base_domain"], "expires_at": sess.ExpiresAt,
		"totp_enabled": user != nil && user.TOTPEnabled,
	})
}

// ---------- settings ----------

var publicSettingKeys = []string{
	"base_domain", "wan_ip", "wan_port", "lan_ip", "gui_port", "wan_iface", "lan_iface",
	"dos_rps", "dos_burst", "asn_block", "stealth_drop", "stealth_ping", "retention_days",
	"sample_above_rps", "max_body", "protection_enabled", "acme_staging", "acme_email",
	"gate_ttl_hours", "home_lat", "home_lon", "decoy_hosts",
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	kv, err := s.st.Settings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	out := map[string]string{}
	for _, k := range publicSettingKeys {
		out[k] = kv[k]
	}
	out["kernel"] = fmt.Sprint(kernelStatus(s.bans))
	out["geoip"] = fmt.Sprint(s.geo.Available())
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
			clean, msg := s.cleanDecoyHosts(v)
			if msg != "" {
				writeError(w, http.StatusBadRequest, msg)
				return
			}
			v = clean
		}
		switch k {
		case "dos_rps", "dos_burst", "retention_days", "sample_above_rps", "max_body", "gate_ttl_hours":
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
	if err := s.st.SetSettings(next); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot save settings")
		return
	}
	_ = s.policy.Reload()
	cur := s.policy.CurrentSettings()
	s.proxy.SetBodyLimit(cur.MaxBody)
	s.bans.SetStealth(cur.StealthPing, cur.WANIface)
	s.metrics.SetInterfaces(cur.WANIface, cur.LANIface)
	if err := s.proxy.Reload(r.Context()); err != nil {
		s.log.Error("reload after settings", "err", err)
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "settings.update", strings.Join(keys(next), ","), clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// cleanDecoyHosts normalizes a comma list and refuses entries that collide with
// a real proxy hostname, so saving the setting can never ban legitimate traffic.
func (s *Server) cleanDecoyHosts(raw string) (string, string) {
	hosts := []string{}
	seen := map[string]bool{}
	proxies, _ := s.st.ListProxies()
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
