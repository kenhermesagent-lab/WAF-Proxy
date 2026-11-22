package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// gateUserHarness drives the gate-account endpoints with an authenticated
// admin session.
type gateUserHarness struct {
	t     *testing.T
	srv   *Server
	st    *store.Store
	token string
	csrf  string
}

type gateUserBody struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	TOTPEnabled bool   `json:"totp_enabled"`
	OTPAuthURL  string `json:"otpauth_url"`
	TOTPSecret  string `json:"totp_secret"`
}

func (h *gateUserHarness) do(method, path string, body any) *httptest.ResponseRecorder {
	h.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			h.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Host = "gui.local"
	req.RemoteAddr = "10.0.0.10:5000"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: h.token})
	req.Header.Set("X-CSRF-Token", h.csrf)
	rec := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(rec, req)
	return rec
}

func (h *gateUserHarness) decode(rec *httptest.ResponseRecorder) gateUserBody {
	h.t.Helper()
	var out gateUserBody
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		h.t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return out
}

// create registers an account and returns its id.
func (h *gateUserHarness) create(username, password string, totp bool) gateUserBody {
	h.t.Helper()
	rec := h.do(http.MethodPost, "/api/gate-users", map[string]any{
		"username": username, "password": password, "totp_enabled": totp,
	})
	if rec.Code != http.StatusCreated {
		h.t.Fatalf("create %s = %d: %s", username, rec.Code, rec.Body.String())
	}
	return h.decode(rec)
}

// stored reads the persisted row, including the sealed TOTP secret.
func (h *gateUserHarness) stored(id int64) model.GateUser {
	h.t.Helper()
	users, err := h.st.ListGateUsers()
	if err != nil {
		h.t.Fatal(err)
	}
	for _, u := range users {
		if u.ID == id {
			return u
		}
	}
	h.t.Fatalf("gate user %d not found", id)
	return model.GateUser{}
}

// TestGateUserTOTPEnabledAfterCreation is the regression test for the lockout
// where an account created without TOTP stored a sealed empty secret, and
// enabling TOTP later reused it, so every code was rejected.
func TestGateUserTOTPEnabledAfterCreation(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	h := &gateUserHarness{t: t, srv: srv, st: st, token: token, csrf: csrf}

	user := h.create("visitor", "visitor-password-1", false)
	if row := h.stored(user.ID); row.TOTPSecret != "" || row.TOTPEnabled {
		t.Fatalf("account without TOTP stored a secret or reported TOTP on: %+v", row)
	}

	// Enabling must issue a secret usable by an authenticator app.
	rec := h.do(http.MethodPut, fmt.Sprintf("/api/gate-users/%d", user.ID), map[string]any{"totp_enabled": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("enable TOTP = %d: %s", rec.Code, rec.Body.String())
	}
	enrolled := h.decode(rec)
	if enrolled.TOTPSecret == "" || enrolled.OTPAuthURL == "" {
		t.Fatalf("enabling TOTP did not return an enrolment secret: %s", rec.Body.String())
	}
	if !strings.Contains(enrolled.OTPAuthURL, enrolled.TOTPSecret) {
		t.Fatalf("otpauth URL does not carry the secret: %s", enrolled.OTPAuthURL)
	}
	row := h.stored(user.ID)
	if !row.TOTPEnabled {
		t.Fatal("TOTP was not persisted as enabled")
	}
	plain, err := srv.box.Open(row.TOTPSecret)
	if err != nil {
		t.Fatalf("stored secret cannot be decrypted: %v", err)
	}
	if plain != enrolled.TOTPSecret {
		t.Fatalf("stored secret %q differs from the one shown once %q", plain, enrolled.TOTPSecret)
	}
	code, err := auth.TOTPCode(plain, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !auth.ValidateTOTP(plain, code, time.Now()) {
		t.Fatal("the freshly issued secret cannot produce a valid code")
	}

	// Disabling keeps the secret, and enabling again must reuse it instead of
	// issuing a second one the account holder has never seen.
	if rec := h.do(http.MethodPut, fmt.Sprintf("/api/gate-users/%d", user.ID), map[string]any{"totp_enabled": false}); rec.Code != http.StatusOK {
		t.Fatalf("disable TOTP = %d: %s", rec.Code, rec.Body.String())
	}
	sealedBefore := h.stored(user.ID).TOTPSecret
	rec = h.do(http.MethodPut, fmt.Sprintf("/api/gate-users/%d", user.ID), map[string]any{"totp_enabled": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("re-enable TOTP = %d: %s", rec.Code, rec.Body.String())
	}
	if again := h.decode(rec); again.TOTPSecret != "" {
		t.Fatalf("re-enabling TOTP issued a new secret instead of reusing the stored one")
	}
	if row := h.stored(user.ID); !row.TOTPEnabled || row.TOTPSecret != sealedBefore {
		t.Fatalf("re-enabling TOTP changed the stored secret: %+v", row)
	}

	// A row written before the fix holds a sealed *empty* string rather than no
	// secret. It must still be treated as "no secret", or the account stays
	// locked out behind a code nobody can produce.
	legacy := h.create("legacy", "legacy-password-1", false)
	sealedEmpty, err := srv.box.Seal("")
	if err != nil {
		t.Fatal(err)
	}
	row = h.stored(legacy.ID)
	if err := st.UpdateGateUser(legacy.ID, row.PasswordHash, sealedEmpty, false); err != nil {
		t.Fatal(err)
	}
	rec = h.do(http.MethodPut, fmt.Sprintf("/api/gate-users/%d", legacy.ID), map[string]any{"totp_enabled": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("enable TOTP on sealed-empty secret = %d: %s", rec.Code, rec.Body.String())
	}
	fresh := h.decode(rec)
	if fresh.TOTPSecret == "" {
		t.Fatal("re-enabling TOTP on a sealed empty secret did not issue a usable secret")
	}
	plain, err = srv.box.Open(h.stored(legacy.ID).TOTPSecret)
	if err != nil || plain != fresh.TOTPSecret {
		t.Fatalf("stored secret for the legacy row is wrong: %q, %v", plain, err)
	}
}

// TestGateUserEditRejectsShortPassword keeps the password policy on the edit
// path as well as on creation.
func TestGateUserEditRejectsShortPassword(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	h := &gateUserHarness{t: t, srv: srv, st: st, token: token, csrf: csrf}
	user := h.create("visitor", "visitor-password-1", false)
	before := h.stored(user.ID).PasswordHash

	rec := h.do(http.MethodPut, fmt.Sprintf("/api/gate-users/%d", user.ID), map[string]any{"password": "short"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("short password on edit = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "12") {
		t.Fatalf("rejection does not explain the length rule: %s", rec.Body.String())
	}
	after := h.stored(user.ID).PasswordHash
	if after != before || !auth.VerifyPassword(after, "visitor-password-1") {
		t.Fatal("a rejected password change modified the stored hash")
	}

	rec = h.do(http.MethodPost, "/api/gate-users", map[string]any{
		"username": "shorty", "password": "short", "totp_enabled": false,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("short password on create = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}
