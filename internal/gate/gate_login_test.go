package gate

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

const (
	gateTestIP = "203.0.113.9"
	// A fixed secret keeps the codes deterministic, so a test can name the
	// current and previous step instead of waiting for a clock boundary.
	gateTestTOTPSecret = "JBSWY3DPEHPK3PXP"
)

// gateFixture is one gate on one store, with the clock pinned so a code cannot
// drift into the next time step part-way through a test.
type gateFixture struct {
	g   *Gate
	st  *store.Store
	box *wfcrypto.Box
	p   *model.Proxy
	now time.Time
}

func newGateFixture(t *testing.T, mode string) *gateFixture {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, err := wfcrypto.New(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	p := &model.Proxy{Hostname: "app.example.com", Enabled: true, GateMode: mode}
	if p.ID, err = st.CreateProxy(p); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return &gateFixture{
		g: &Gate{
			st: st, box: box, limiter: auth.NewLimiter(), now: func() time.Time { return now },
			log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		st:  st,
		box: box,
		now: now,
		p:   p,
	}
}

func (f *gateFixture) createUser(t *testing.T, username, password, secret string) {
	t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	sealed := ""
	if secret != "" {
		if sealed, err = f.box.Seal(secret); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.st.CreateGateUser(username, hash, sealed, secret != ""); err != nil {
		t.Fatal(err)
	}
}

func (f *gateFixture) post(t *testing.T, form string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "http://"+f.p.Hostname+LoginPath, strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	if !f.g.Handle(rec, r, f.p, netip.MustParseAddr(gateTestIP)) {
		t.Fatal("the gate did not handle a login post")
	}
	return rec
}

func (f *gateFixture) login(t *testing.T, username, password, code string) *httptest.ResponseRecorder {
	t.Helper()
	return f.post(t, url.Values{
		"username": {username}, "password": {password}, "totp": {code}, "next": {"/"},
	}.Encode(), nil)
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == CookieName {
			return c
		}
	}
	return nil
}

// An unknown account must cost one password hash, so the login form cannot be
// used to learn which gate usernames exist from response timing.
func TestGateLoginHashesForAnUnknownAccount(t *testing.T) {
	f := newGateFixture(t, "accounts")

	hashed := 0
	prev := dummyVerify
	dummyVerify = func(string) { hashed++ }
	defer func() { dummyVerify = prev }()

	rec := f.login(t, "admin", "wrong", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if hashed != 1 {
		t.Fatalf("argon2 ran %d times for an unknown account, want 1", hashed)
	}
}

// A wrong password must look the same whether the account exists or not.
func TestGateLoginUniformFailureForUnknownAccount(t *testing.T) {
	f := newGateFixture(t, "accounts")
	f.createUser(t, "real", "right password", "")

	known := f.login(t, "real", "wrong password", "")
	unknown := f.login(t, "ghost", "wrong password", "")
	if known.Code != http.StatusUnauthorized || unknown.Code != known.Code {
		t.Fatalf("status real=%d unknown=%d, want both 401", known.Code, unknown.Code)
	}
	if known.Body.String() != unknown.Body.String() {
		t.Fatal("the failure page differs between a real and an unknown account")
	}
}

func TestGateTOTPCodeRejectedOnReplay(t *testing.T) {
	f := newGateFixture(t, "accounts_totp")
	f.createUser(t, "visitor", "correct horse", gateTestTOTPSecret)
	code, err := auth.TOTPCode(gateTestTOTPSecret, f.now)
	if err != nil {
		t.Fatal(err)
	}

	first := f.login(t, "visitor", "correct horse", code)
	if first.Code != http.StatusSeeOther {
		t.Fatalf("first sign-in = %d, want 303", first.Code)
	}
	if sessionCookie(first) == nil {
		t.Fatal("the first sign-in issued no session cookie")
	}

	again := f.login(t, "visitor", "correct horse", code)
	if again.Code != http.StatusUnauthorized {
		t.Fatalf("replayed code = %d, want 401", again.Code)
	}
	if sessionCookie(again) != nil {
		t.Fatal("a replayed code issued a session cookie")
	}
}

// The previous step is still inside the accepted window, so only the claimed
// step stops it. An attacker replaying a code seen one step ago must be refused.
func TestGateTOTPPreviousStepRejected(t *testing.T) {
	f := newGateFixture(t, "accounts_totp")
	f.createUser(t, "visitor", "correct horse", gateTestTOTPSecret)
	current, err := auth.TOTPCode(gateTestTOTPSecret, f.now)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := auth.TOTPCode(gateTestTOTPSecret, f.now.Add(-30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if current == previous {
		t.Fatal("adjacent steps produced the same code; pick another test secret")
	}

	if rec := f.login(t, "visitor", "correct horse", current); rec.Code != http.StatusSeeOther {
		t.Fatalf("current step = %d, want 303", rec.Code)
	}
	rec := f.login(t, "visitor", "correct horse", previous)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("previous step = %d, want 401", rec.Code)
	}
	if sessionCookie(rec) != nil {
		t.Fatal("a previous-step code issued a session cookie")
	}
}

func TestGateLoginRejectsCrossOriginPost(t *testing.T) {
	f := newGateFixture(t, "passphrase")

	for _, tc := range []struct{ name, origin, fetchSite string }{
		{name: "other origin", origin: "https://evil.example"},
		{name: "opaque origin", origin: "null"},
		{name: "fetch metadata", fetchSite: "cross-site"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.post(t, "password=guess&next=%2F",
				map[string]string{"Origin": tc.origin, "Sec-Fetch-Site": tc.fetchSite})
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
			if sessionCookie(rec) != nil {
				t.Fatal("a cross-site post issued a session cookie")
			}
		})
	}

	// The site's own form, and a client that sends no browser headers, are served.
	if rec := f.post(t, "password=guess&next=%2F", map[string]string{"Origin": "http://" + f.p.Hostname}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("same-origin post = %d, want 401 (a wrong passphrase, not a refusal)", rec.Code)
	}
	if rec := f.login(t, "", "guess", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("headerless post = %d, want 401", rec.Code)
	}
}
