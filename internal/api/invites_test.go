package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// An invitation link creates an enrolled account once, and the link stops
// working afterwards.
func TestInvitationCreatesEnrolledAccount(t *testing.T) {
	h := newAccountHarness(t)
	token := "test-invite-token"
	if err := h.st.CreateInvite(tokenDigest(token), "new@example.com", "New", "Admin",
		h.st.AdminRoleID(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	info := httptest.NewRequest(http.MethodGet, "https://gui.local/api/invite?token="+token, nil)
	info.Host = "gui.local"
	rec := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(rec, info)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "new@example.com") {
		t.Fatalf("invite info = %d: %s", rec.Code, rec.Body.String())
	}

	created := h.public(t, "/api/invite/accept", map[string]string{
		"token": token, "username": "newadmin", "password": "correct horse battery",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("accept = %d: %s", created.Code, created.Body.String())
	}
	if !strings.Contains(created.Body.String(), `"totp_secret"`) {
		t.Fatalf("accept did not return an authenticator secret: %s", created.Body.String())
	}
	user, err := h.st.UserByUsername("newadmin")
	if err != nil || user.Email != "new@example.com" || !user.TOTPEnabled {
		t.Fatalf("invited account = %+v (%v)", user, err)
	}

	if again := h.public(t, "/api/invite/accept", map[string]string{
		"token": token, "username": "other", "password": "correct horse battery",
	}); again.Code != http.StatusBadRequest {
		t.Fatalf("a spent invitation was accepted again: %d", again.Code)
	}
}
