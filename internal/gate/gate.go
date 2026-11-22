// Package gate implements the optional per-proxy access gate (shared passphrase,
// accounts with TOTP, or an external forward-auth provider) and the
// login-failure ban escalation ladder.
package gate

import (
	"context"
	"crypto/subtle"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/safepath"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

const (
	// LoginPath is intercepted by the proxy before routing.
	LoginPath    = "/__wafproxy/gate"
	cookieName   = "__wfp_gate"
	maxFormBytes = 4096
)

// Gate evaluates and serves the access gate.
type Gate struct {
	st      *store.Store
	box     *crypto.Box
	bans    *ban.Engine
	limiter *auth.Limiter
	log     *slog.Logger
	ttl     time.Duration
	ttlAt   time.Time
	ttlMu   sync.Mutex
	now     func() time.Time

	// OnBan is called when the escalation ladder applies a ban.
	OnBan func(ip, reason string, permanent bool)
}

// New returns a gate bound to the store and ban engine.
func New(st *store.Store, box *crypto.Box, bans *ban.Engine, log *slog.Logger) *Gate {
	return &Gate{
		st:      st,
		box:     box,
		bans:    bans,
		limiter: auth.NewLimiter(),
		log:     log,
		ttl:     12 * time.Hour,
		now:     time.Now,
	}
}

// Start prunes expired account-lockout buckets.
func (g *Gate) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				g.limiter.Cleanup()
			}
		}
	}()
}

// Enabled reports whether the proxy uses a gate.
func Enabled(p *model.Proxy) bool {
	return p.GateMode != "" && p.GateMode != "off"
}

// Handle serves the gate. It returns true when it has fully handled the request.
func (g *Gate) Handle(w http.ResponseWriter, r *http.Request, p *model.Proxy, src netip.Addr) bool {
	if !Enabled(p) {
		return false
	}
	if isHealthPath(r.URL.Path) {
		return false
	}
	if p.GateMode == "forward_auth" {
		return g.forwardAuth(w, r, p)
	}

	if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
		if _, ok := g.st.LookupGateSession(c.Value, p.ID); ok {
			return false
		}
	}

	if r.URL.Path == LoginPath && r.Method == http.MethodPost {
		g.login(w, r, p, src)
		return true
	}
	// Never reveal a different response for unknown paths while unauthenticated.
	g.renderLogin(w, p, r.URL.RequestURI(), "", http.StatusOK)
	return true
}

func isHealthPath(path string) bool {
	switch path {
	case "/healthz", "/health", "/__health", "/__wafproxy/health":
		return true
	}
	return strings.HasPrefix(path, "/.well-known/acme-challenge/")
}

func (g *Gate) login(w http.ResponseWriter, r *http.Request, p *model.Proxy, src netip.Addr) {
	ip := src.String()
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		g.fail(w, p, src, "", "bad-request")
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	totp := strings.TrimSpace(r.PostFormValue("totp"))
	next := safepath.Next(r.PostFormValue("next"))

	// Account lockout works even when the attacker rotates source IPs.
	if username != "" && !g.limiter.Allow("user:"+username, 5, 15*time.Minute) {
		g.fail(w, p, src, username, "lockout")
		return
	}
	// A username block is checked before the password so an agent can cut off a
	// compromised account immediately. DummyVerify keeps the response timing
	// close to a normal bad password.
	if username != "" {
		banned, err := g.st.UsernameBanned(username)
		if err != nil {
			g.log.Error("check username ban", "err", err)
		}
		if banned {
			auth.DummyVerify(password)
			g.fail(w, p, src, username, "blocked-username")
			return
		}
	}

	ok := false
	switch p.GateMode {
	case "passphrase":
		secret, err := g.box.Open(p.GateSecret)
		if err == nil && secret != "" {
			ok = subtle.ConstantTimeCompare([]byte(secret), []byte(password)) == 1
		}
	default: // accounts, accounts_totp
		user, err := g.st.GateUserByUsername(username)
		if err == nil && user != nil && auth.VerifyPassword(user.PasswordHash, password) {
			ok = g.allowed(p.ID, user.Username)
			if ok && p.GateMode == "accounts_totp" {
				secret, serr := g.box.Open(user.TOTPSecret)
				if serr != nil || !user.TOTPEnabled || !auth.ValidateTOTP(secret, totp, g.now()) {
					ok = false
				}
			}
		}
	}

	if !ok {
		g.fail(w, p, src, username, "bad-credentials")
		return
	}

	token, err := crypto.RandomToken(32)
	if err != nil {
		g.renderLogin(w, p, next, "temporary error", http.StatusInternalServerError)
		return
	}
	expires := g.now().Add(g.sessionTTL())
	if err := g.st.CreateGateSession(token, p.ID, username, ip, r.UserAgent(), expires); err != nil {
		g.log.Error("create gate session", "err", err)
		g.renderLogin(w, p, next, "temporary error", http.StatusInternalServerError)
		return
	}
	_ = g.st.ClearGateFailures(ip)
	g.limiter.Reset("user:" + username)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
	if next == "" {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (g *Gate) allowed(proxyID int64, username string) bool {
	if banned, err := g.st.UsernameBanned(username); err != nil || banned {
		return false
	}
	acl, err := g.st.GateACL(proxyID)
	if err != nil {
		return false
	}
	if len(acl) == 0 {
		return true
	}
	for _, name := range acl {
		if name == username {
			return true
		}
	}
	return false
}

func (g *Gate) fail(w http.ResponseWriter, p *model.Proxy, src netip.Addr, username, reason string) {
	ip := src.String()
	_ = g.st.RecordGateFailure(ip, p.ID, username, reason)
	last10m, last24h, days, err := g.st.GateFailureStats(ip)
	if err != nil {
		g.log.Error("gate failure stats", "err", err)
	}
	var ttl time.Duration
	permanent := false
	switch {
	case days >= 3 && last24h >= 10:
		permanent = true
	case last24h >= 10:
		ttl = 24 * time.Hour
	case last10m >= 3:
		ttl = 15 * time.Minute
	}
	if ttl > 0 || permanent {
		if _, err := g.bans.Add(ip, fmt.Sprintf("access gate: %s (%d failures/24h)", reason, last24h), "gate", "gate", ttl); err != nil {
			g.log.Warn("gate ban failed", "ip", ip, "err", err)
		} else if g.OnBan != nil {
			g.OnBan(ip, reason, permanent)
		}
	}
	// Uniform response for every failure mode.
	g.renderLogin(w, p, "", "Invalid credentials.", http.StatusUnauthorized)
}

// sessionTTL reads gate_ttl_hours at most once a minute so the GUI setting
// takes effect without a per-request database read.
func (g *Gate) sessionTTL() time.Duration {
	g.ttlMu.Lock()
	defer g.ttlMu.Unlock()
	if !g.ttlAt.IsZero() && g.now().Sub(g.ttlAt) < time.Minute {
		return g.ttl
	}
	g.ttlAt = g.now()
	if raw, err := g.st.GetSetting("gate_ttl_hours"); err == nil && raw != "" {
		if hours, err := strconv.Atoi(raw); err == nil && hours >= 1 && hours <= 720 {
			g.ttl = time.Duration(hours) * time.Hour
		}
	}
	return g.ttl
}

func (g *Gate) renderLogin(w http.ResponseWriter, p *model.Proxy, next, msg string, status int) {
	host := html.EscapeString(p.Hostname)
	next = html.EscapeString(next)
	totpField := ""
	userField := ""
	if p.GateMode == "accounts" || p.GateMode == "accounts_totp" {
		userField = `<label>Username<input name="username" autocomplete="username" required autofocus></label>`
	}
	if p.GateMode == "accounts_totp" {
		totpField = `<label>Authenticator code<input name="totp" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required></label>`
	}
	notice := ""
	if msg != "" {
		notice = `<p class="err">` + html.EscapeString(msg) + `</p>`
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Authentication required</title><style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b0d10;color:#e6e9ef;
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
.card{width:min(380px,92vw);padding:28px;border:1px solid #232936;border-radius:14px;background:#11151c;
box-shadow:0 20px 60px rgba(0,0,0,.45)}
h1{margin:0 0 4px;font-size:18px;font-weight:600;letter-spacing:.2px}
p.sub{margin:0 0 20px;color:#8b93a3;font-size:13px}
label{display:block;margin:0 0 12px;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#9aa4b5}
input{width:100%%;margin-top:6px;padding:10px 12px;border-radius:9px;border:1px solid #2a3140;background:#0d1117;
color:#e6e9ef;font-size:14px;text-transform:none;letter-spacing:normal}
input:focus{outline:none;border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.18)}
button{width:100%%;margin-top:6px;padding:11px;border:0;border-radius:9px;background:#3b82f6;color:#fff;
font-weight:600;font-size:14px;cursor:pointer}
button:hover{background:#2f74e0}
.err{margin:0 0 14px;padding:9px 11px;border-radius:8px;background:#2a1418;border:1px solid #5b2530;color:#f2a7b3;font-size:13px}
.foot{margin-top:18px;color:#5f6878;font-size:11px;text-align:center}
</style></head><body><main class="card">
<h1>Authentication required</h1><p class="sub">%s</p>
%s
<form method="post" action="%s" autocomplete="on">
<input type="hidden" name="next" value="%s">
%s
<label>Password<input name="password" type="password" autocomplete="current-password" required%s></label>
%s
<button type="submit">Continue</button></form>
<p class="foot">Unauthorized access is monitored and logged.</p>
</main></body></html>`,
		host, notice, LoginPath, next, userField, boolAttr(userField == ""), totpField)
}

func boolAttr(b bool) string {
	if b {
		return " autofocus"
	}
	return ""
}
