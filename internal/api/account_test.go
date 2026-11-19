package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/config"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

type accountHarness struct {
	srv      *Server
	st       *store.Store
	box      *wfcrypto.Box
	userID   int64
	token    string
	csrf     string
	secret   string
	recovery string
}

func newAccountHarness(t *testing.T) *accountHarness {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	box, err := wfcrypto.New(bytes.Repeat([]byte{0x24}, 32))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.Seal(secret)
	if err != nil {
		t.Fatal(err)
	}
	codes, stored, err := auth.NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	sealedCodes, err := box.Seal(stored)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := st.CreateUser("admin", hash, sealed, sealedCodes, true)
	if err != nil {
		t.Fatal(err)
	}
	token, err := wfcrypto.RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := wfcrypto.RandomToken(24)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(token, uid, csrf, "192.168.101.10", "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// A second session represents another browser that a rotation must revoke.
	other, _ := wfcrypto.RandomToken(32)
	if err := st.CreateSession(other, uid, "other-csrf", "192.168.101.11", "other", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	bans, err := ban.New(st, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(st, box, &config.Config{}, nil, nil, bans, nil, nil, nil, metrics.New("", ""), nil, nil, log)
	t.Cleanup(func() { _ = st.Close() })
	return &accountHarness{srv: srv, st: st, box: box, userID: uid, token: token, csrf: csrf,
		secret: secret, recovery: codes[0]}
}

func (h *accountHarness) post(t *testing.T, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://gui.local"+path, bytes.NewReader(raw))
	req.Host = "gui.local"
	req.RemoteAddr = "192.168.101.10:5000"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", h.csrf)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: h.token})
	rec := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(rec, req)
	return rec
}

func totp(secret string) string {
	code, _ := auth.TOTPCode(secret, time.Now())
	return code
}

func TestPasswordRotationRevokesOtherSessions(t *testing.T) {
	h := newAccountHarness(t)
	newPassword := "an even better passphrase"

	badCode := "000000"
	if totp(h.secret) == badCode {
		badCode = "111111"
	}
	rec := h.post(t, "/api/account/password", map[string]string{
		"current_password": "correct horse battery", "new_password": newPassword, "totp": badCode,
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong TOTP status = %d, want 401", rec.Code)
	}

	rec = h.post(t, "/api/account/password", map[string]string{
		"current_password": "correct horse battery", "new_password": newPassword, "totp": totp(h.secret),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("password change status = %d: %s", rec.Code, rec.Body.String())
	}
	user, err := h.st.UserByID(h.userID)
	if err != nil {
		t.Fatal(err)
	}
	if !auth.VerifyPassword(user.PasswordHash, newPassword) {
		t.Fatal("new password does not verify")
	}
	if auth.VerifyPassword(user.PasswordHash, "correct horse battery") {
		t.Fatal("old password still verifies")
	}
	if _, err := h.st.LookupSession(h.token); err != nil {
		t.Fatal("current session was revoked")
	}
	// The harness's second session must be gone; session count proves it.
	if n, err := h.st.CountUserSessions(h.userID); err != nil || n != 1 {
		t.Fatalf("sessions after rotation = %d (%v), want 1", n, err)
	}
}

func TestTOTPRotationAndRecoveryCodes(t *testing.T) {
	h := newAccountHarness(t)
	rec := h.post(t, "/api/account/totp", map[string]string{
		"current_password": "correct horse battery", "totp": totp(h.secret),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("begin TOTP status = %d: %s", rec.Code, rec.Body.String())
	}
	var begin struct {
		Secret string `json:"secret"`
		URL    string `json:"otpauth_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &begin); err != nil {
		t.Fatal(err)
	}
	if begin.Secret == "" || !strings.HasPrefix(begin.URL, "otpauth://totp/") {
		t.Fatalf("bad enrolment payload: %+v", begin)
	}

	rec = h.post(t, "/api/account/totp/confirm", map[string]string{
		"secret": begin.Secret, "code": totp(begin.Secret),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm TOTP status = %d: %s", rec.Code, rec.Body.String())
	}
	var done struct {
		Codes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &done); err != nil {
		t.Fatal(err)
	}
	if len(done.Codes) != 10 {
		t.Fatalf("recovery codes = %d, want 10", len(done.Codes))
	}
	// Pending state is single-use: a stolen session cannot replay confirmation.
	replay := h.post(t, "/api/account/totp/confirm", map[string]string{
		"secret": begin.Secret, "code": totp(begin.Secret),
	})
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replayed confirmation status = %d, want 400", replay.Code)
	}
	user, _ := h.st.UserByID(h.userID)
	plain, err := h.box.Open(user.TOTPSecret)
	if err != nil || plain != begin.Secret {
		t.Fatalf("stored TOTP secret mismatch: %q (%v)", plain, err)
	}
	// Rotation also invalidates the extra session.
	if n, _ := h.st.CountUserSessions(h.userID); n != 1 {
		t.Fatalf("sessions after TOTP rotation = %d, want 1", n)
	}
}

// Recovery codes are the documented way back in when the authenticator is
// lost, so signing in with one must work and must burn it.
func TestLoginWithRecoveryCodeIsSingleUse(t *testing.T) {
	h := newAccountHarness(t)
	body := map[string]string{
		"username": "admin", "password": "correct horse battery", "recovery": h.recovery,
	}
	rec := h.post(t, "/api/login", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("recovery login status = %d: %s", rec.Code, rec.Body.String())
	}
	if len(rec.Result().Cookies()) == 0 {
		t.Fatal("recovery login did not issue a session cookie")
	}
	rec = h.post(t, "/api/login", body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("reused recovery login status = %d, want 401", rec.Code)
	}
}

// A recovery code must be able to rotate the lost second factor; otherwise an
// operator who signed in with a recovery code could never regain a working
// authenticator, and every use of the code must still be single-use.
func TestRecoveryCodeRotatesTOTPOnce(t *testing.T) {
	h := newAccountHarness(t)
	rec := h.post(t, "/api/account/totp", map[string]string{
		"current_password": "correct horse battery", "recovery": h.recovery,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("begin with recovery code status = %d: %s", rec.Code, rec.Body.String())
	}
	var begin struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &begin); err != nil {
		t.Fatal(err)
	}
	if begin.Secret == "" || begin.Secret == h.secret {
		t.Fatalf("recovery rotation returned a bad secret: %q", begin.Secret)
	}

	// The same code is spent: it cannot authorise a second credential change.
	replay := h.post(t, "/api/account/password", map[string]string{
		"current_password": "correct horse battery", "new_password": "another long passphrase",
		"recovery": h.recovery,
	})
	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("reused recovery code status = %d, want 401", replay.Code)
	}

	rec = h.post(t, "/api/account/totp/confirm", map[string]string{
		"secret": begin.Secret, "code": totp(begin.Secret),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm status = %d: %s", rec.Code, rec.Body.String())
	}
	user, err := h.st.UserByID(h.userID)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := h.box.Open(user.TOTPSecret); err != nil || plain != begin.Secret {
		t.Fatalf("stored TOTP secret = %q (%v), want the rotated secret", plain, err)
	}
}

func TestLogoutEverywhere(t *testing.T) {
	h := newAccountHarness(t)
	rec := h.post(t, "/api/account/logout-all", map[string]string{})
	if rec.Code != http.StatusOK {
		t.Fatalf("logout-all status = %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := h.st.LookupSession(h.token); err == nil {
		t.Fatal("current session survived logout-all")
	}
	if n, _ := h.st.CountUserSessions(h.userID); n != 0 {
		t.Fatalf("sessions after logout-all = %d, want 0", n)
	}
}
