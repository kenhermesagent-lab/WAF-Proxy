package gate

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// verifyClient keeps connections to the provider warm, because a site behind
// forward-auth makes one verification request per browser request.
var verifyClient = &http.Client{
	Timeout: 5 * time.Second,
	// The provider's redirect is the login page; following it here would fetch
	// the portal for every unauthenticated request.
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// forwardAuth delegates the access decision to an external provider. The
// provider answers 2xx for a caller it has already authenticated, a redirect to
// its own login, or 401. Anything else fails closed: a provider that is down
// must not open the site.
func (g *Gate) forwardAuth(w http.ResponseWriter, r *http.Request, p *model.Proxy) bool {
	if p.AuthProviderID == nil {
		g.log.Error("forward-auth proxy has no provider", "host", p.Hostname)
		g.deny(w, http.StatusServiceUnavailable, "no identity provider is attached to this site.")
		return true
	}
	provider, err := g.st.GetAuthProvider(*p.AuthProviderID)
	if err != nil || provider == nil {
		g.log.Error("forward-auth provider missing", "host", p.Hostname, "err", err)
		g.deny(w, http.StatusServiceUnavailable, "the identity provider for this site is not configured.")
		return true
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	original := scheme + "://" + p.Hostname + r.URL.RequestURI()

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, provider.VerifyURL, nil)
	if err != nil {
		g.log.Error("build forward-auth request", "provider", provider.Name, "err", err)
		g.deny(w, http.StatusServiceUnavailable, "the identity provider could not be reached.")
		return true
	}
	req.Header.Set("X-Forwarded-Method", r.Method)
	req.Header.Set("X-Forwarded-Proto", scheme)
	req.Header.Set("X-Forwarded-Host", p.Hostname)
	req.Header.Set("X-Forwarded-Uri", r.URL.RequestURI())
	req.Header.Set("X-Original-URL", original)
	for _, h := range []string{"Cookie", "User-Agent", "Authorization", "Accept-Language"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	if provider.Header != "" {
		if secret, err := g.box.Open(provider.Secret); err == nil && secret != "" {
			req.Header.Set(provider.Header, secret)
		}
	}

	resp, err := verifyClient.Do(req)
	if err != nil {
		g.log.Warn("forward-auth unavailable", "provider", provider.Name, "err", err)
		g.deny(w, http.StatusServiceUnavailable, "the identity provider could not be reached.")
		return true
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false
	case resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.Header.Get("Location") != "":
		http.Redirect(w, r, safeProviderURL(resp.Header.Get("Location"), provider), http.StatusFound)
	case resp.StatusCode == http.StatusUnauthorized && provider.LoginURL != "":
		http.Redirect(w, r, loginRedirect(provider.LoginURL, original), http.StatusFound)
	default:
		g.deny(w, http.StatusUnauthorized, "sign-in with the identity provider failed.")
	}
	return true
}

// safeProviderURL keeps the redirect on the provider: a relative path is
// resolved against the provider's own origin, never against the proxied site.
func safeProviderURL(location string, provider *model.AuthProvider) string {
	base, err := url.Parse(provider.VerifyURL)
	if err != nil {
		return provider.LoginURL
	}
	ref, err := url.Parse(location)
	if err != nil {
		return provider.LoginURL
	}
	return base.ResolveReference(ref).String()
}

func loginRedirect(loginURL, original string) string {
	u, err := url.Parse(loginURL)
	if err != nil {
		return loginURL
	}
	q := u.Query()
	q.Set("rd", original)
	u.RawQuery = q.Encode()
	return u.String()
}

// deny renders the same generic page for every failure, so an unauthenticated
// caller cannot tell a missing provider from a rejected login.
func (g *Gate) deny(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Access unavailable</title><style>
:root{color-scheme:dark}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b0d10;
color:#e6e9ef;font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
.card{width:min(420px,92vw);padding:26px;border:1px solid #232936;border-radius:14px;background:#11151c}
h1{margin:0 0 6px;font-size:17px}p{margin:0;color:%s;font-size:13px}
</style></head><body><main class="card"><h1>Access unavailable</h1>
<p>%s</p></main></body></html>`, "#8b93a3", html.EscapeString(msg))
}
