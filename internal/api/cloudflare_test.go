package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func (h *accountHarness) send(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "https://gui.local"+path, reader)
	req.Host = "gui.local"
	req.RemoteAddr = "10.0.0.10:5000"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", h.csrf)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: h.token})
	rec := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(rec, req)
	return rec
}

const testTunnelToken = "eyJhIjoiYWNjb3VudCIsInQiOiJ0dW5uZWwiLCJzIjoic2VjcmV0In0="

func TestCloudflareStatusHidesToken(t *testing.T) {
	h := newAccountHarness(t)
	rec := h.get(t, "/api/cloudflare")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "eyJ") {
		t.Fatalf("response leaked a token: %s", body)
	}
	var view cloudflareView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Enabled || view.TokenSet {
		t.Fatalf("fresh install reports %+v", view)
	}
	if view.State == "" {
		t.Fatal("state is empty; the page needs a connector state")
	}
}

func TestCloudflareTokenIsSealedAndShownOnlyByTail(t *testing.T) {
	h := newAccountHarness(t)
	rec := h.send(t, http.MethodPut, "/api/cloudflare", map[string]any{"token": testTunnelToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("save token = %d: %s", rec.Code, rec.Body.String())
	}
	sealed, err := h.st.GetSetting("cloudflare_tunnel_token")
	if err != nil {
		t.Fatal(err)
	}
	if sealed == "" || sealed == testTunnelToken || strings.Contains(sealed, "eyJ") {
		t.Fatalf("token stored as %q", sealed)
	}

	get := h.get(t, "/api/cloudflare")
	if strings.Contains(get.Body.String(), testTunnelToken) {
		t.Fatal("status leaked the token")
	}
	var view cloudflareView
	if err := json.Unmarshal(get.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.TokenSet || view.TokenTail != testTunnelToken[len(testTunnelToken)-4:] {
		t.Fatalf("token flags = %+v", view)
	}
}

// The connector serves every site, so its token is a host setting. A console
// opened on a tenant site must not see an empty token because it reads its own
// site's settings table.
func TestCloudflareSettingsAreHostScoped(t *testing.T) {
	h := newAccountHarness(t)
	if rec := h.send(t, http.MethodPut, "/api/cloudflare", map[string]any{"token": testTunnelToken}); rec.Code != http.StatusOK {
		t.Fatalf("save token = %d: %s", rec.Code, rec.Body.String())
	}
	host, err := h.st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if host["cloudflare_tunnel_token"] == "" {
		t.Fatal("token was not written to the host settings")
	}
	site, err := h.st.SettingsFor(42)
	if err != nil {
		t.Fatal(err)
	}
	if site["cloudflare_tunnel_token"] != host["cloudflare_tunnel_token"] {
		t.Fatal("a tenant site does not read the host's connector token")
	}
	scoped, err := h.st.InSite(42).Settings()
	if err != nil {
		t.Fatal(err)
	}
	if scoped["cloudflare_tunnel_token"] == "" {
		t.Fatal("a tenant site's console sees no connector token")
	}
}

func TestCloudflareEnableRequiresToken(t *testing.T) {
	h := newAccountHarness(t)
	rec := h.send(t, http.MethodPut, "/api/cloudflare", map[string]any{"enabled": true})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("enable without a token = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCloudflareRejectsMalformedTokenAndTunnelID(t *testing.T) {
	h := newAccountHarness(t)
	if rec := h.send(t, http.MethodPut, "/api/cloudflare", map[string]any{"token": "short"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("short token = %d", rec.Code)
	}
	if rec := h.send(t, http.MethodPut, "/api/cloudflare", map[string]any{"tunnel_id": "not-a-uuid"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad tunnel id = %d", rec.Code)
	}
}

// Saving a setting the page can see must not overwrite the token it cannot see.
func TestCloudflareSaveWithoutTokenKeepsIt(t *testing.T) {
	h := newAccountHarness(t)
	if rec := h.send(t, http.MethodPut, "/api/cloudflare", map[string]any{"token": testTunnelToken}); rec.Code != http.StatusOK {
		t.Fatalf("token save = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := h.send(t, http.MethodPut, "/api/cloudflare", map[string]any{"strict_origin": false, "tunnel_id": ""}); rec.Code != http.StatusOK {
		t.Fatalf("settings save = %d: %s", rec.Code, rec.Body.String())
	}
	var view cloudflareView
	if err := json.Unmarshal(h.get(t, "/api/cloudflare").Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.TokenSet || view.StrictOrigin {
		t.Fatalf("view = %+v", view)
	}
}

func TestCloudflareCheckRefusesForeignHostname(t *testing.T) {
	h := newAccountHarness(t)
	rec := h.send(t, http.MethodPost, "/api/cloudflare/check", map[string]any{"hostnames": []string{"someone-else.example.com"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("foreign hostname = %d: %s", rec.Code, rec.Body.String())
	}
}

// The tunnel check reads this marker back through the edge; it must appear only
// once a nonce has been generated by saving the page.
func TestCloudflareHealthCarriesOriginNonce(t *testing.T) {
	h := newAccountHarness(t)
	if rec := h.send(t, http.MethodPut, "/api/cloudflare", map[string]any{"token": testTunnelToken}); rec.Code != http.StatusOK {
		t.Fatalf("save = %d: %s", rec.Code, rec.Body.String())
	}
	nonce, err := h.st.GetSetting("cloudflare_check_nonce")
	if err != nil || nonce == "" {
		t.Fatalf("nonce = %q (%v)", nonce, err)
	}
	throughConnector := httptest.NewRequest(http.MethodGet, "https://gui.local/api/health", nil)
	throughConnector.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(rec, throughConnector)
	if got := rec.Header().Get("X-WAF-Origin"); got != nonce {
		t.Fatalf("health origin header = %q, want the saved nonce", got)
	}

	// A visitor reaching the listener from the network cannot read the marker.
	direct := httptest.NewRequest(http.MethodGet, "https://gui.local/api/health", nil)
	direct.RemoteAddr = "198.51.100.7:5555"
	directRec := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(directRec, direct)
	if got := directRec.Header().Get("X-WAF-Origin"); got != "" {
		t.Fatalf("direct health response leaked the nonce %q", got)
	}
}

func TestCloudflareConnectorNeedsToken(t *testing.T) {
	h := newAccountHarness(t)
	rec := h.send(t, http.MethodPost, "/api/cloudflare/connector", map[string]any{"action": "start"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("start without token = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := h.send(t, http.MethodPost, "/api/cloudflare/connector", map[string]any{"action": "explode"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown action = %d", rec.Code)
	}
}

// Without the host helper the install button must explain itself instead of
// running anything.
func TestCloudflareInstallReportsUnsupportedHost(t *testing.T) {
	h := newAccountHarness(t)
	var st cloudflareInstall
	if err := json.Unmarshal(h.get(t, "/api/cloudflare/install").Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Supported || st.Reason == "" {
		t.Fatalf("install status = %+v", st)
	}
	if rec := h.post(t, "/api/cloudflare/install", map[string]any{}); rec.Code != http.StatusConflict {
		t.Fatalf("install on unsupported host = %d: %s", rec.Code, rec.Body.String())
	}
}
