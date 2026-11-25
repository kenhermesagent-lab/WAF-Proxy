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

// TestScanOnlyGateAccountIsSealedAndBound proves the scanner account is minted
// as a machine credential: flagged scan_only, sealed for the scanner, bound to
// the hostnames named at creation, and listed with the scanner as its origin.
func TestScanOnlyGateAccountIsSealedAndBound(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	h := &gateUserHarness{t: t, srv: srv, st: st, token: token, csrf: csrf}
	proxyID, err := st.CreateProxy(&model.Proxy{Hostname: "app.example.com", Enabled: true, GateMode: "accounts"})
	if err != nil {
		t.Fatal(err)
	}

	rec := h.do(http.MethodPost, "/api/gate-users", map[string]any{
		"username": "scanner", "scan_only": true, "proxies": []int64{proxyID},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create scan account = %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID           int64  `json:"id"`
		ScanOnly     bool   `json:"scan_only"`
		ScanPassword string `json:"scan_password"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if !created.ScanOnly || created.ScanPassword == "" {
		t.Fatalf("scan account response = %+v, want a generated password shown once", created)
	}

	account, err := st.ScanGateUser(proxyID)
	if err != nil {
		t.Fatalf("the scan account was not bound: %v", err)
	}
	if !account.ScanOnly || account.Origin != "scanner" || account.ScanSecret == "" {
		t.Fatalf("stored scan account = %+v", account)
	}
	plain, err := srv.box.Open(account.ScanSecret)
	if err != nil || plain != created.ScanPassword {
		t.Fatalf("sealed scan password = %q, %v; want the one shown once", plain, err)
	}
	if !auth.VerifyPassword(account.PasswordHash, created.ScanPassword) {
		t.Fatal("the scan account's hash does not verify the generated password")
	}
	acl, err := st.GateACL(proxyID)
	if err != nil {
		t.Fatal(err)
	}
	if len(acl) != 1 || acl[0] != "scanner" {
		t.Fatalf("bound hostnames = %v, want the scanner only", acl)
	}

	// The list names the scanner as the account's origin and never carries the
	// sealed password back out.
	list := h.do(http.MethodGet, "/api/gate-users", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", list.Code, list.Body.String())
	}
	if !strings.Contains(list.Body.String(), `"origin":"scanner"`) {
		t.Fatalf("the list does not name the scanner origin: %s", list.Body.String())
	}
	if strings.Contains(list.Body.String(), created.ScanPassword) {
		t.Fatal("the account list leaked the scan password")
	}

	// A scanner cannot produce a one-time code, so a second factor is refused.
	rec = h.do(http.MethodPost, "/api/gate-users", map[string]any{
		"username": "scanner-totp", "scan_only": true, "totp_enabled": true,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("scan account with TOTP = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	rec = h.do(http.MethodPut, fmt.Sprintf("/api/gate-users/%d", created.ID), map[string]any{"totp_enabled": true})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("enabling TOTP on a scan account = %d, want 400: %s", rec.Code, rec.Body.String())
	}

	// A password change must move the sealed copy with the hash.
	rec = h.do(http.MethodPut, fmt.Sprintf("/api/gate-users/%d", created.ID), map[string]any{"password": "rotated-scan-password-1"})
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate scan password = %d: %s", rec.Code, rec.Body.String())
	}
	account, err = st.ScanGateUser(proxyID)
	if err != nil {
		t.Fatal(err)
	}
	plain, err = srv.box.Open(account.ScanSecret)
	if err != nil || plain != "rotated-scan-password-1" {
		t.Fatalf("sealed password after rotation = %q, %v", plain, err)
	}
	if !auth.VerifyPassword(account.PasswordHash, "rotated-scan-password-1") {
		t.Fatal("the rotated hash does not verify the rotated password")
	}
}
