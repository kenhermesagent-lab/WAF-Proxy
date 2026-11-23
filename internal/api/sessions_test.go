package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The account menu's signed-in list must show the caller's other browsers with
// their addresses, and must not leak the session cookie value into JSON.
func TestActiveSessionsListsLiveBrowsers(t *testing.T) {
	h := newAccountHarness(t)
	req := httptest.NewRequest(http.MethodGet, "https://gui.local/api/sessions", nil)
	req.Host = "gui.local"
	req.RemoteAddr = "10.0.0.10:5000"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: h.token})
	rec := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Count    int `json:"count"`
		Sessions []struct {
			Username  string `json:"username"`
			IP        string `json:"ip"`
			CreatedAt string `json:"created_at"`
			ExpiresAt string `json:"expires_at"`
			Current   bool   `json:"current"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Count != 2 || len(out.Sessions) != 2 {
		t.Fatalf("count = %d, sessions = %d, want 2", out.Count, len(out.Sessions))
	}
	current := 0
	ips := map[string]bool{}
	for _, s := range out.Sessions {
		if s.Current {
			current++
		}
		ips[s.IP] = true
		if s.Username != "admin" || s.CreatedAt == "" || s.ExpiresAt == "" {
			t.Fatalf("session = %+v, want the admin with both timestamps", s)
		}
	}
	if current != 1 {
		t.Fatalf("sessions marked current = %d, want 1", current)
	}
	if !ips["10.0.0.10"] || !ips["10.0.0.11"] {
		t.Fatalf("source addresses = %v, want both browsers", ips)
	}
	if body := rec.Body.String(); strings.Contains(body, h.token) {
		t.Fatal("the session cookie value is in the response")
	}
}
