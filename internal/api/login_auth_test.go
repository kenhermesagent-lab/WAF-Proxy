package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func (h *accountHarness) public(t *testing.T, path string, body any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://gui.local"+path, bytes.NewReader(raw))
	req.Host = "gui.local"
	req.RemoteAddr = "10.0.0.10:5000"
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(rec, req)
	return rec
}

func deviceCookieFrom(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == deviceCookie && c.Value != "" {
			return c
		}
	}
	return nil
}

// A remembered browser must pass the second factor without a code, and a
// browser without the cookie must still be rejected.
func TestRememberDeviceSkipsTOTP(t *testing.T) {
	h := newAccountHarness(t)
	first := h.public(t, "/api/login", map[string]any{
		"username": "admin", "password": "correct horse battery",
		"totp": totp(h.secret), "remember": true,
	})
	if first.Code != http.StatusOK {
		t.Fatalf("remembered login status = %d: %s", first.Code, first.Body.String())
	}
	device := deviceCookieFrom(t, first)
	if device == nil {
		t.Fatal("remembered login did not set a device cookie")
	}
	if n, _ := h.st.CountUserSessions(h.userID); n != 3 {
		t.Fatalf("sessions = %d, want 3", n)
	}

	second := h.public(t, "/api/login", map[string]string{
		"username": "admin", "password": "correct horse battery",
	}, device)
	if second.Code != http.StatusOK {
		t.Fatalf("login with remembered device status = %d: %s", second.Code, second.Body.String())
	}

	bare := h.public(t, "/api/login", map[string]string{
		"username": "admin", "password": "correct horse battery",
	})
	if bare.Code != http.StatusUnauthorized {
		t.Fatalf("login without code or device status = %d, want 401", bare.Code)
	}
}

// A recovery login returns a replacement secret the console can confirm, and
// leaves the stored authenticator untouched until that confirmation.
func TestRecoveryLoginOffersReplacementTOTP(t *testing.T) {
	h := newAccountHarness(t)
	rec := h.public(t, "/api/login", map[string]string{
		"username": "admin", "password": "correct horse battery", "recovery": h.recovery,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("recovery login status = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		RecoveryUsed bool   `json:"recovery_used"`
		Secret       string `json:"totp_secret"`
		URL          string `json:"otpauth_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.RecoveryUsed || out.Secret == "" || !strings.HasPrefix(out.URL, "otpauth://totp/") {
		t.Fatalf("recovery login did not offer a new authenticator: %+v", out)
	}
	user, _ := h.st.UserByID(h.userID)
	plain, err := h.box.Open(user.TOTPSecret)
	if err != nil || plain != h.secret {
		t.Fatalf("stored secret changed before confirmation: %q (%v)", plain, err)
	}
}

func TestPasswordResetTokenIsSingleUse(t *testing.T) {
	h := newAccountHarness(t)
	token := strings.Repeat("r", 40)
	if err := h.st.CreatePasswordReset(tokenDigest(token), h.userID, time.Now().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	rec := h.public(t, "/api/password/reset", map[string]string{
		"token": token, "password": "a replacement passphrase",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("reset status = %d: %s", rec.Code, rec.Body.String())
	}
	if n, _ := h.st.CountUserSessions(h.userID); n != 0 {
		t.Fatalf("sessions after reset = %d, want 0", n)
	}
	replay := h.public(t, "/api/password/reset", map[string]string{
		"token": token, "password": "another replacement passphrase",
	})
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replayed reset status = %d, want 400", replay.Code)
	}
	login := h.public(t, "/api/login", map[string]string{
		"username": "admin", "password": "a replacement passphrase", "totp": totp(h.secret),
	})
	if login.Code != http.StatusOK {
		t.Fatalf("login with reset password status = %d: %s", login.Code, login.Body.String())
	}
	old := h.public(t, "/api/login", map[string]string{
		"username": "admin", "password": "correct horse battery", "totp": totp(h.secret),
	})
	if old.Code != http.StatusUnauthorized {
		t.Fatalf("old password status = %d, want 401", old.Code)
	}
}

func TestForgotPasswordNeedsEmailChannel(t *testing.T) {
	h := newAccountHarness(t)
	req := httptest.NewRequest(http.MethodGet, "https://gui.local/api/password/forgot", nil)
	req.Host = "gui.local"
	rec := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"available":false`) {
		t.Fatalf("availability = %d %s", rec.Code, rec.Body.String())
	}
	post := h.public(t, "/api/password/forgot", map[string]string{"username": "admin"})
	if post.Code != http.StatusBadRequest {
		t.Fatalf("forgot without email status = %d, want 400", post.Code)
	}
}
