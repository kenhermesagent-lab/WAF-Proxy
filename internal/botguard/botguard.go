// Package botguard implements a stateless JavaScript proof-of-work challenge.
package botguard

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/safepath"
)

const (
	// SolvePath receives the proof-of-work solution.
	SolvePath  = "/__wafproxy/bot"
	cookieName = "__wfp_bot"
)

// Levels maps a per-proxy level to a difficulty.
var Levels = map[string]int{
	"off":        0,
	"light":      2,
	"standard":   3,
	"aggressive": 4,
}

// Guard issues and verifies challenge cookies.
type Guard struct {
	secret   []byte
	bans     *ban.Engine
	st       storeLogger
	failures *auth.Limiter
	log      *slog.Logger
	now      func() time.Time
	ttl      time.Duration
}

type storeLogger interface {
	RecordGateFailure(ip string, proxyID int64, username, reason string) error
}

// New returns a guard signing cookies with secret.
func New(secret []byte, bans *ban.Engine, st storeLogger, log *slog.Logger) *Guard {
	return &Guard{
		secret:   secret,
		bans:     bans,
		st:       st,
		failures: auth.NewLimiter(),
		log:      log,
		now:      time.Now,
		ttl:      24 * time.Hour,
	}
}

// Start prunes expired failure buckets so a public gate cannot grow the map
// without bound.
func (g *Guard) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				g.failures.Cleanup()
			}
		}
	}()
}

// Verified reports whether the request carries a valid challenge cookie for
// this client. The address is part of the binding, so a solved proof cannot be
// replayed from another host.
func (g *Guard) Verified(r *http.Request, ip string) bool {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return false
	}
	return g.validCookie(c.Value, r, ip)
}

// BrowserLike reports whether a request looks like a navigation, which is the
// only traffic the challenge is applied to. API clients and non-HTML requests
// are never challenged so machine clients keep working.
func BrowserLike(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	a := r.Header.Get("Accept")
	return strings.Contains(a, "text/html") || strings.Contains(a, "application/xhtml+xml")
}

func (g *Guard) validCookie(value string, r *http.Request, ip string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || g.now().Unix() > exp {
		return false
	}
	mac := hmac.New(sha256.New, g.secret)
	mac.Write([]byte("bot|" + parts[0] + "|" + clientKey(r, ip)))
	want := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(parts[1]))
}

func clientKey(r *http.Request, ip string) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host + "|" + r.UserAgent() + "|" + clientNetwork(ip)
}

// clientNetwork binds the cookie to the network an address belongs to. IPv4 is
// exact; IPv6 uses its /64 because one subscriber rotates addresses freely
// inside that block, and treating each as a new client would break the cookie
// for half the internet.
func clientNetwork(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	p, err := a.Prefix(64)
	if err != nil {
		return a.String()
	}
	return p.String()
}

// HandleChallenge serves the challenge page or verifies a solution.
func (g *Guard) HandleChallenge(w http.ResponseWriter, r *http.Request, p *model.Proxy, ip string) bool {
	level := p.BotLevel
	difficulty := Levels[level]
	if difficulty == 0 {
		return false
	}
	if r.URL.Path == SolvePath && r.Method == http.MethodPost {
		g.solve(w, r, p, ip, difficulty)
		return true
	}
	nonce, err := wfcrypto.RandomToken(16)
	if err != nil {
		return false
	}
	g.render(w, r, p, nonce, difficulty)
	return true
}

func (g *Guard) solve(w http.ResponseWriter, r *http.Request, p *model.Proxy, ip string, difficulty int) {
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	if err := r.ParseForm(); err != nil {
		g.reject(w, ip, p)
		return
	}
	nonce := r.PostFormValue("nonce")
	solution := r.PostFormValue("solution")
	if !Verify(nonce, solution, difficulty) {
		g.reject(w, ip, p)
		return
	}
	exp := g.now().Add(g.ttl).Unix()
	payload := strconv.FormatInt(exp, 10) + "|" + clientKey(r, ip)
	mac := hmac.New(sha256.New, g.secret)
	mac.Write([]byte("bot|" + payload))
	value := strconv.FormatInt(exp, 10) + "." + hex.EncodeToString(mac.Sum(nil))
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: value, Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
		Expires: time.Unix(exp, 0),
	})
	next := safepath.Next(r.PostFormValue("next"))
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (g *Guard) reject(w http.ResponseWriter, ip string, p *model.Proxy) {
	key := "bot:" + ip
	if !g.failures.Allow(key, 5, 10*time.Minute) {
		if _, err := g.bans.Add(ip, "bot challenge failed repeatedly", "bot", "botguard", time.Hour); err != nil {
			g.log.Warn("bot ban failed", "ip", ip, "err", err)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Request blocked.\n"))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte("Challenge verification failed.\n"))
}

// Verify checks that sha256(nonce+solution) has the required leading zeros.
func Verify(nonce, solution string, difficulty int) bool {
	if nonce == "" || solution == "" || len(nonce) > 64 || len(solution) > 64 {
		return false
	}
	sum := sha256.Sum256([]byte(nonce + solution))
	hexed := hex.EncodeToString(sum[:])
	return strings.HasPrefix(hexed, strings.Repeat("0", difficulty))
}

func (g *Guard) render(w http.ResponseWriter, r *http.Request, p *model.Proxy, nonce string, difficulty int) {
	host := html.EscapeString(p.Hostname)
	next := html.EscapeString(safepath.Next(r.URL.RequestURI()))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Checking your browser</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b0d10;color:#e6e9ef;
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
.card{width:min(360px,92vw);padding:26px;border:1px solid #232936;border-radius:14px;background:#11151c;text-align:center}
h1{margin:0 0 6px;font-size:17px;font-weight:600}p{margin:0;color:#8b93a3;font-size:13px}
.bar{height:3px;margin-top:18px;border-radius:2px;background:#1c2330;overflow:hidden}
.bar i{display:block;height:100%%;width:0;background:#3b82f6;transition:width .2s}
</style></head><body><main class="card">
<h1>Checking your browser</h1><p>%s</p><div class="bar"><i id="p"></i></div>
<form id="f" method="post" action="%s"><input type="hidden" name="next" value="%s">
<input type="hidden" name="nonce" value="%s"><input type="hidden" name="solution" id="s"></form>
</main><script>
const nonce=%q,difficulty=%d,target="0".repeat(difficulty);
const enc=new TextEncoder();let n=0;
async function sha(x){const b=await crypto.subtle.digest("SHA-256",enc.encode(x));
return [...new Uint8Array(b)].map(v=>v.toString(16).padStart(2,"0")).join("")}
(async()=>{for(;;){const h=await sha(nonce+n);
if(h.startsWith(target)){document.getElementById("s").value=String(n);
document.getElementById("p").style.width="100%%";setTimeout(()=>document.getElementById("f").submit(),150);break}
if((n&1023)===0){document.getElementById("p").style.width=Math.min(95,n/20000)+"%%";
await new Promise(r=>setTimeout(r,0))}n++}})();
</script></body></html>`, host, SolvePath, next, nonce, nonce, difficulty)
}
