package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func listIDStr(id int64) string { return strconv.FormatInt(id, 10) }

func createList(t *testing.T, srv *Server, token, csrf, body string) model.AccessList {
	t.Helper()
	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/lists", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/lists = %d: %s", rec.Code, rec.Body.String())
	}
	var l model.AccessList
	if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil {
		t.Fatalf("decode list %q: %v", rec.Body.String(), err)
	}
	return l
}

// The console pastes one entry per line and mixes bare addresses with CIDRs;
// the stored form is canonical, so the engine parses the same thing every time.
func TestAccessListEntriesAreNormalized(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	l := createList(t, srv, token, csrf,
		"{\"kind\":\"blocklist\",\"name\":\" Scanners \",\"ips\":\"198.51.100.9\\n203.0.113.0/24\\n198.51.100.9\",\"countries\":\"ru, de\"}")
	if l.Name != "Scanners" {
		t.Errorf("name = %q, want Scanners", l.Name)
	}
	if l.IPs != "198.51.100.9/32,203.0.113.0/24" {
		t.Errorf("ips = %q, want the canonical list", l.IPs)
	}
	if l.Countries != "RU,DE" {
		t.Errorf("countries = %q, want RU,DE", l.Countries)
	}
}

func TestAccessListRejectsBadEntries(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	cases := map[string]string{
		"a typo in an address": `{"kind":"blocklist","name":"t","ips":"203.0.113.999"}`,
		"an unknown kind":      `{"kind":"denylist","name":"t","ips":"203.0.113.7"}`,
		"an empty name":        `{"kind":"whitelist","name":"  ","ips":"203.0.113.7"}`,
		"a country word":       `{"kind":"whitelist","name":"t","countries":"Germany"}`,
	}
	for name, body := range cases {
		rec := authed(t, srv, token, csrf, http.MethodPost, "/api/lists", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (%s)", name, rec.Code, rec.Body.String())
		}
	}
}

func TestAccessListNameIsUniqueAndImmutable(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	l := createList(t, srv, token, csrf, `{"kind":"whitelist","name":"Office","ips":"203.0.113.7"}`)

	dup := authed(t, srv, token, csrf, http.MethodPost, "/api/lists",
		`{"kind":"blocklist","name":"Office","ips":"198.51.100.9"}`)
	if dup.Code != http.StatusConflict {
		t.Fatalf("duplicate name = %d, want 409 (%s)", dup.Code, dup.Body.String())
	}

	upd := authed(t, srv, token, csrf, http.MethodPut, "/api/lists/"+listIDStr(l.ID),
		`{"kind":"blocklist","name":"Renamed","ips":"198.51.100.9"}`)
	if upd.Code != http.StatusOK {
		t.Fatalf("PUT /api/lists/%d = %d: %s", l.ID, upd.Code, upd.Body.String())
	}
	var saved model.AccessList
	if err := json.Unmarshal(upd.Body.Bytes(), &saved); err != nil {
		t.Fatalf("decode update: %v", err)
	}
	if saved.Kind != model.ListKindAllow || saved.Name != "Office" {
		t.Fatalf("kind or name changed on update: %+v", saved)
	}
	if saved.IPs != "198.51.100.9/32" {
		t.Fatalf("entries were not replaced: %+v", saved)
	}
}

// A profile that references a list keeps working; deleting a list out from
// under it is refused so the site cannot silently lose its policy.
func TestAccessListAttachesToProfileAndRefusesDeleteInUse(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	l := createList(t, srv, token, csrf, `{"kind":"blocklist","name":"Scanners","ips":"198.51.100.0/24"}`)

	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/access-profiles",
		`{"name":"Guarded","rules":[],"list_ids":[`+listIDStr(l.ID)+`]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/access-profiles = %d: %s", rec.Code, rec.Body.String())
	}
	var prof model.AccessProfile
	if err := json.Unmarshal(rec.Body.Bytes(), &prof); err != nil {
		t.Fatalf("decode profile: %v", err)
	}
	if len(prof.ListIDs) != 1 || prof.ListIDs[0] != l.ID {
		t.Fatalf("profile did not keep its list: %+v", prof.ListIDs)
	}

	del := authed(t, srv, token, csrf, http.MethodDelete, "/api/lists/"+listIDStr(l.ID), "")
	if del.Code != http.StatusConflict {
		t.Fatalf("delete in use = %d, want 409 (%s)", del.Code, del.Body.String())
	}

	bad := authed(t, srv, token, csrf, http.MethodPost, "/api/access-profiles",
		`{"name":"Broken","rules":[],"list_ids":[9999]}`)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("unknown list reference = %d, want 400 (%s)", bad.Code, bad.Body.String())
	}
}
