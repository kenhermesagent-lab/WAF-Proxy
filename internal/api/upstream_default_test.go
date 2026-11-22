package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// Naming an upstream without saying whether it is enabled must leave it live:
// a site whose only upstream was stored disabled answers 502 for everyone.
func TestUpstreamDefaultsToEnabled(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}

	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/proxies",
		`{"hostname":"app.example.com","upstreams":[{"url":"http://192.168.1.10:8080"}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/proxies = %d: %s", rec.Code, rec.Body.String())
	}
	var created model.Proxy
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	ups, err := st.ListUpstreams(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 1 || !ups[0].Enabled {
		t.Fatalf("an omitted enabled field stored %+v", ups)
	}

	rec = authed(t, srv, token, csrf, http.MethodPut, "/api/proxies/"+strconv.FormatInt(created.ID, 10),
		`{"upstreams":[{"url":"http://192.168.1.10:8080","enabled":false}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/proxies = %d: %s", rec.Code, rec.Body.String())
	}
	ups, err = st.ListUpstreams(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 1 || ups[0].Enabled {
		t.Fatalf("an explicit false did not disable the upstream: %+v", ups)
	}
}
