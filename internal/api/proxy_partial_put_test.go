package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
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
