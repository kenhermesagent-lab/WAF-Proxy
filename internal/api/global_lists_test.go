package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// The global list attachment refuses a list of the wrong kind and round-trips
// the IDs it accepts, so the console can trust what it reads back.
func TestGlobalListsEndpoints(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	list := &model.AccessList{Kind: model.ListKindBlock, Name: "scanners", IPs: "198.51.100.0/24"}
	if err := srv.st.CreateAccessList(list); err != nil {
		t.Fatal(err)
	}
	id := strconv.FormatInt(list.ID, 10)

	rec := authed(t, srv, token, csrf, http.MethodPut, "/api/global-lists",
		`{"whitelist_ids":[`+id+`],"blocklist_ids":[]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a blocklist in the whitelist field = %d, want 400", rec.Code)
	}

	rec = authed(t, srv, token, csrf, http.MethodPut, "/api/global-lists",
		`{"whitelist_ids":[],"blocklist_ids":[`+id+`]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/global-lists = %d: %s", rec.Code, rec.Body.String())
	}

	rec = authed(t, srv, token, csrf, http.MethodGet, "/api/global-lists", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/global-lists = %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		WhitelistIDs []int64 `json:"whitelist_ids"`
		BlocklistIDs []int64 `json:"blocklist_ids"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.WhitelistIDs) != 0 || len(got.BlocklistIDs) != 1 || got.BlocklistIDs[0] != list.ID {
		t.Fatalf("attached lists did not round-trip: %+v", got)
	}
}

// A list applied under Global Profile cannot be deleted from its own tab: the
// deletion would remove it from the Whitelist tab while the engine quietly
// stopped enforcing it.
func TestGlobalListCannotBeDeletedWhileAttached(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	list := &model.AccessList{Kind: model.ListKindAllow, Name: "office", IPs: "203.0.113.7"}
	if err := srv.st.CreateAccessList(list); err != nil {
		t.Fatal(err)
	}
	id := strconv.FormatInt(list.ID, 10)

	rec := authed(t, srv, token, csrf, http.MethodPut, "/api/global-lists",
		`{"whitelist_ids":[`+id+`],"blocklist_ids":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/global-lists = %d: %s", rec.Code, rec.Body.String())
	}

	rec = authed(t, srv, token, csrf, http.MethodDelete, "/api/lists/"+id, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("deleting an attached list = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Global Profile") {
		t.Fatalf("the refusal does not say where the list is attached: %s", rec.Body.String())
	}

	if rec := authed(t, srv, token, csrf, http.MethodPut, "/api/global-lists",
		`{"whitelist_ids":[],"blocklist_ids":[]}`); rec.Code != http.StatusOK {
		t.Fatalf("detaching = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := authed(t, srv, token, csrf, http.MethodDelete, "/api/lists/"+id, ""); rec.Code != http.StatusOK {
		t.Fatalf("deleting a detached list = %d: %s", rec.Code, rec.Body.String())
	}
}
