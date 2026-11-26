package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/botguard"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/gate"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/policy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/proxy"
)

// A partial PUT carries only what the caller changed. It used to clear the
// upstream pool and detach the WAF profile of the site it was editing, so a
// one-field edit took the site offline and left it unfiltered.
func TestPartialPutKeepsUpstreamsAndProfile(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}

	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/profiles", `{"name":"In use"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create profile = %d: %s", rec.Code, rec.Body.String())
	}
	var profile model.Profile
	if err := json.Unmarshal(rec.Body.Bytes(), &profile); err != nil {
		t.Fatal(err)
	}

	rec = authed(t, srv, token, csrf, http.MethodPost, "/api/proxies",
		`{"hostname":"app.example.com","profile_id":`+strconv.FormatInt(profile.ID, 10)+
			`,"upstreams":[{"url":"http://192.168.1.10:8080"}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/proxies = %d: %s", rec.Code, rec.Body.String())
	}
	var created model.Proxy
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	path := "/api/proxies/" + strconv.FormatInt(created.ID, 10)
	rec = authed(t, srv, token, csrf, http.MethodPut, path, `{"maintenance":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/proxies = %d: %s", rec.Code, rec.Body.String())
	}
	stored, err := st.GetProxy(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ProfileID == nil || *stored.ProfileID != profile.ID {
		t.Fatalf("a partial PUT detached the WAF profile: %v", stored.ProfileID)
	}
	ups, err := st.ListUpstreams(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 1 || ups[0].URL != "http://192.168.1.10:8080" {
		t.Fatalf("a partial PUT changed the upstream pool: %+v", ups)
	}
	if !stored.Maintenance {
		t.Fatal("the field the PUT named did not change")
	}

	// An explicit empty list still empties the pool, so the API keeps a way to
	// take a site out of rotation on purpose.
	rec = authed(t, srv, token, csrf, http.MethodPut, path, `{"upstreams":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/proxies = %d: %s", rec.Code, rec.Body.String())
	}
	if ups, err = st.ListUpstreams(created.ID); err != nil {
		t.Fatal(err)
	} else if len(ups) != 0 {
		t.Fatalf("an explicit empty upstream list did not clear the pool: %+v", ups)
	}
}

// Removing a closed path through the site save reopens it: the stored list
// loses the entry and the live proxy serves the upstream again.
func TestRemoveDenyPathThroughProxySaveServesItAgain(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "served")
	}))
	t.Cleanup(app.Close)
	id, err := st.CreateProxy(&model.Proxy{
		Hostname: "app.example.com", Enabled: true, WAFMode: "off",
		DenyPaths: []string{"/actuator", "/.env"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceUpstreams(id, []model.Upstream{{ProxyID: id, URL: app.URL, Weight: 1, Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.New(st, srv.bans, nil, nil, nil, srv.log)
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(proxy.Deps{
		Store: st, Policy: pol, Gate: gate.New(st, srv.box, srv.bans, srv.log),
		Bots:    botguard.New(bytes.Repeat([]byte{0x42}, 32), srv.bans, st, srv.log),
		Bans:    srv.bans,
		Geo:     geoip.Open(t.TempDir()),
		Metrics: srv.metrics,
		Log:     srv.log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := px.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv.proxy, srv.policy = px, pol

	get := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/actuator/env", nil)
		req.Host = "app.example.com"
		req.RemoteAddr = "10.0.0.11:5000"
		rec := httptest.NewRecorder()
		px.ServeHTTP(rec, req)
		return rec
	}
	if rec := get(); rec.Code != http.StatusForbidden {
		t.Fatalf("a closed path answered %d (%s), want 403", rec.Code, rec.Body.String())
	}

	rec := securityDo(t, srv, http.MethodPut, "/api/proxies/"+strconv.FormatInt(id, 10), "gui.local", token, csrf,
		map[string]any{"deny_paths": []string{"/.env"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/proxies = %d: %s", rec.Code, rec.Body.String())
	}
	stored, err := st.GetProxy(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.DenyPaths) != 1 || stored.DenyPaths[0] != "/.env" {
		t.Fatalf("stored deny paths = %v, want only /.env", stored.DenyPaths)
	}
	if rec := get(); rec.Code != http.StatusOK || rec.Body.String() != "served" {
		t.Fatalf("reopened path answered %d %q, want the upstream", rec.Code, rec.Body.String())
	}
}

// The body ceiling and the skip paths are part of the site's configuration, so
// they round-trip, an explicit empty list clears them, and a bad entry is
// refused instead of stored.
func TestProxyBodySettingsRoundTrip(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}

	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/lists",
		`{"name":"Office","kind":"whitelist","ips":"10.0.0.0/8"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create list = %d: %s", rec.Code, rec.Body.String())
	}
	var list model.AccessList
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}

	rec = authed(t, srv, token, csrf, http.MethodPost, "/api/proxies",
		`{"hostname":"app.example.com","max_body":268435456,`+
			`"body_skip":[{"method":"POST","prefix":"/api/assets","list_ids":[`+strconv.FormatInt(list.ID, 10)+`]}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/proxies = %d: %s", rec.Code, rec.Body.String())
	}
	var created model.Proxy
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	stored, err := st.GetProxy(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.MaxBody != 268435456 {
		t.Fatalf("stored max_body = %d, want 268435456", stored.MaxBody)
	}
	if len(stored.BodySkip) != 1 || stored.BodySkip[0].Method != "POST" ||
		stored.BodySkip[0].Prefix != "/api/assets" ||
		len(stored.BodySkip[0].ListIDs) != 1 || stored.BodySkip[0].ListIDs[0] != list.ID {
		t.Fatalf("stored body_skip = %+v, want the POST /api/assets entry with the list", stored.BodySkip)
	}

	path := "/api/proxies/" + strconv.FormatInt(created.ID, 10)
	// A field the PUT does not name keeps its value, and an explicit empty list
	// still clears the skip paths on purpose.
	if rec := authed(t, srv, token, csrf, http.MethodPut, path, `{"maintenance":true}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/proxies = %d: %s", rec.Code, rec.Body.String())
	}
	if stored, err = st.GetProxy(created.ID); err != nil {
		t.Fatal(err)
	} else if stored.MaxBody != 268435456 || len(stored.BodySkip) != 1 {
		t.Fatalf("a partial PUT changed the body settings: %+v", stored)
	}
	if rec := authed(t, srv, token, csrf, http.MethodPut, path, `{"body_skip":[]}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/proxies = %d: %s", rec.Code, rec.Body.String())
	}
	if stored, err = st.GetProxy(created.ID); err != nil {
		t.Fatal(err)
	} else if len(stored.BodySkip) != 0 || stored.MaxBody != 268435456 {
		t.Fatalf("an explicit empty body_skip did not clear it: %+v", stored)
	}

	for _, bad := range []string{
		`{"body_skip":[{"method":"GET","prefix":"/x"}]}`,
		`{"body_skip":[{"method":"POST","prefix":"/"}]}`,
		`{"body_skip":[{"method":"POST","prefix":"api"}]}`,
		`{"body_skip":[{"method":"POST","prefix":"/x","list_ids":[999999]}]}`,
		`{"max_body":2147483648}`,
	} {
		if rec := authed(t, srv, token, csrf, http.MethodPut, path, bad); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 400", bad, rec.Code)
		}
	}
	if stored, err = st.GetProxy(created.ID); err != nil {
		t.Fatal(err)
	} else if len(stored.BodySkip) != 0 || stored.MaxBody != 268435456 {
		t.Fatalf("a refused PUT still changed the body settings: %+v", stored)
	}
}
