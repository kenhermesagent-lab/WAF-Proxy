package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func TestCloudflareAppsPublishOnlySiteHostnames(t *testing.T) {
	h := newAccountHarness(t)
	if _, err := h.srv.st.CreateProxy(&model.Proxy{Hostname: "app.example.com"}); err != nil {
		t.Fatal(err)
	}
	rec := h.send(t, http.MethodGet, "/api/cloudflare/apps", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("apps = %d: %s", rec.Code, rec.Body.String())
	}
	var view cloudflareAppsView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Apps) != 1 || view.Apps[0].Published {
		t.Fatalf("fresh view = %+v", view)
	}
	if want := "https://127.0.0.1:443"; view.Apps[0].Service != want {
		t.Fatalf("service = %q, want %q", view.Apps[0].Service, want)
	}

	rec = h.send(t, http.MethodPut, "/api/cloudflare/apps", map[string]any{
		"published": []string{"app.example.com"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("publish = %d: %s", rec.Code, rec.Body.String())
	}
	view = cloudflareAppsView{}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	app := view.Apps[0]
	if !app.Published || app.OriginName != "app.example.com" || !app.NoTLSVerify {
		t.Fatalf("published row = %+v", app)
	}

	// A hostname the site does not proxy is refused rather than published.
	rec = h.send(t, http.MethodPut, "/api/cloudflare/apps", map[string]any{
		"published": []string{"elsewhere.example.net"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("foreign host publish = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCloudflarePublishListIsPerSite(t *testing.T) {
	f := newSiteFixtures(t)
	bravo := f.st.InSite(f.bravo.ID)
	if _, err := bravo.CreateProxy(&model.Proxy{Hostname: "app.bravo.test"}); err != nil {
		t.Fatal(err)
	}
	rec := f.call("console.bravo.test", http.MethodPut, "/api/cloudflare/apps", f.bravoToken, f.bravoCSRF, "",
		map[string]any{"published": []string{"app.bravo.test"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("bravo publish = %d: %s", rec.Code, rec.Body.String())
	}
	rec = f.call("gui.local", http.MethodGet, "/api/cloudflare/apps", f.adminToken, f.adminCSRF, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("default apps = %d: %s", rec.Code, rec.Body.String())
	}
	var view cloudflareAppsView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Apps) != 0 {
		t.Fatalf("default site sees bravo's hostnames: %+v", view.Apps)
	}
	kv, err := f.st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if kv["cloudflare_published_hosts"] != "" {
		t.Fatalf("bravo's publish list leaked into host settings: %q", kv["cloudflare_published_hosts"])
	}
}
