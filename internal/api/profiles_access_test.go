package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// A profile with no lists used to be stored with a nil rules slice, which the
// console renders as JSON null and then crashes on.
func TestAccessProfileWithoutRulesKeepsEmptyList(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)

	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/access-profiles",
		`{"name":"Bare profile","rules":null}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/access-profiles = %d: %s", rec.Code, rec.Body.String())
	}
	var created model.AccessProfile
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created profile %q: %v", rec.Body.String(), err)
	}
	if created.ID == 0 {
		t.Fatalf("created profile has no id: %+v", created)
	}

	list := authed(t, srv, token, csrf, http.MethodGet, "/api/access-profiles", "")
	var profiles []model.AccessProfile
	if err := json.Unmarshal(list.Body.Bytes(), &profiles); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	for _, a := range profiles {
		if a.ID != created.ID {
			continue
		}
		if a.Rules == nil {
			t.Fatalf("profile %d has nil rules: %s", a.ID, list.Body.String())
		}
		if len(a.Rules) != 0 {
			t.Fatalf("profile %d has unexpected rules: %+v", a.ID, a.Rules)
		}
		return
	}
	t.Fatalf("created profile is missing from GET /api/access-profiles: %s", list.Body.String())
}

// The console's toggle sends the whole list, but any other client that leaves
// enabled or priority out must not switch the list off or reset its order.
func TestPolicyUpdateKeepsOmittedFields(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)

	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/policies",
		`{"kind":"ip_whitelist","value":"198.51.100.0/24","priority":42}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/policies = %d: %s", rec.Code, rec.Body.String())
	}
	var created model.Policy
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created policy %q: %v", rec.Body.String(), err)
	}
	if created.ID == 0 || !created.Enabled || created.Priority != 42 {
		t.Fatalf("unexpected created policy: %+v", created)
	}

	upd := authed(t, srv, token, csrf, http.MethodPut,
		"/api/policies/"+strconv.FormatInt(created.ID, 10),
		`{"kind":"ip_whitelist","value":"198.51.100.0/24","note":"office"}`)
	if upd.Code != http.StatusOK {
		t.Fatalf("PUT /api/policies/%d = %d: %s", created.ID, upd.Code, upd.Body.String())
	}
	var updated model.Policy
	if err := json.Unmarshal(upd.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode updated policy %q: %v", upd.Body.String(), err)
	}
	if !updated.Enabled || updated.Priority != 42 || updated.Note != "office" {
		t.Fatalf("update dropped stored fields: %+v", updated)
	}
}
