package botguard

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func solvedCookie(t *testing.T, g *Guard, host, ua, ip string) *http.Cookie {
	t.Helper()
	const nonce = "0123456789abcdef"
	solution := ""
	for i := 0; i < 100000 && solution == ""; i++ {
		if s := strconv.Itoa(i); Verify(nonce, s, Levels["light"]) {
			solution = s
		}
	}
	if solution == "" {
		t.Fatal("no proof-of-work solution found")
	}
	form := url.Values{"nonce": {nonce}, "solution": {solution}, "next": {"/"}}
	req := httptest.NewRequest(http.MethodPost, SolvePath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = host
	req.Header.Set("User-Agent", ua)
	rec := httptest.NewRecorder()
	proxy := &model.Proxy{Hostname: host, BotLevel: "light"}
	if !g.HandleChallenge(rec, req, proxy, ip) {
		t.Fatal("the challenge was not handled")
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	t.Fatal("no challenge cookie was issued")
	return nil
}

func checkCookie(c *http.Cookie, host, ua string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = host
	req.Header.Set("User-Agent", ua)
	req.AddCookie(c)
	return req
}

// A solved proof is bound to the site, the browser and the client's network, so
// it cannot be replayed from an address that never paid for it.
func TestChallengeCookieIsBoundToTheClientNetwork(t *testing.T) {
	g := New([]byte("test secret"), nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c := solvedCookie(t, g, "app.example.com", "Mozilla/5.0", "203.0.113.7")

	if !g.Verified(checkCookie(c, "app.example.com", "Mozilla/5.0"), "203.0.113.7") {
		t.Fatal("the issuing client was rejected")
	}
	if g.Verified(checkCookie(c, "app.example.com", "Mozilla/5.0"), "203.0.113.8") {
		t.Fatal("a cookie solved on one IPv4 address worked from another")
	}
	if g.Verified(checkCookie(c, "other.example.com", "Mozilla/5.0"), "203.0.113.7") {
		t.Fatal("the cookie is not bound to the host")
	}
	if g.Verified(checkCookie(c, "app.example.com", "curl/8"), "203.0.113.7") {
		t.Fatal("the cookie is not bound to the user agent")
	}
}

// Stripping the port at the first colon cut an IPv6 Host header down to "[2001",
// so two unrelated IPv6 sites shared a binding and a cookie solved on one was
// accepted by the other.
func TestChallengeCookieKeepsIPv6HostsApart(t *testing.T) {
	g := New([]byte("test secret"), nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c := solvedCookie(t, g, "[2001:db8::1]:443", "Mozilla/5.0", "203.0.113.7")

	if !g.Verified(checkCookie(c, "[2001:db8::1]:443", "Mozilla/5.0"), "203.0.113.7") {
		t.Fatal("the issuing host was rejected")
	}
	if g.Verified(checkCookie(c, "[2001:db8::2]:443", "Mozilla/5.0"), "203.0.113.7") {
		t.Fatal("a cookie solved on one IPv6 host worked on another")
	}
}

// IPv6 clients rotate addresses inside their /64 constantly, so that block is
// the unit the cookie follows.
func TestChallengeCookieFollowsAnIPv6Slash64(t *testing.T) {
	g := New([]byte("test secret"), nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c := solvedCookie(t, g, "app.example.com", "Mozilla/5.0", "2001:db8:1:2::1")

	if !g.Verified(checkCookie(c, "app.example.com", "Mozilla/5.0"), "2001:db8:1:2::99") {
		t.Fatal("a rotating address in the same /64 was rejected")
	}
	if g.Verified(checkCookie(c, "app.example.com", "Mozilla/5.0"), "2001:db8:1:3::1") {
		t.Fatal("a cookie worked from a different /64")
	}
}
