package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
)

func TestBulkBansPromoteAndRemove(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)

	ids := make([]int64, 0, 2)
	for _, cidr := range []string{"203.0.113.9", "198.51.100.4"} {
		rec := authed(t, srv, token, csrf, http.MethodPost, "/api/bans",
			`{"cidr":"`+cidr+`","reason":"bulk test","ttl_seconds":3600}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create ban %s = %d: %s", cidr, rec.Code, rec.Body.String())
		}
		var created struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, created.ID)
	}

	// A duplicate id must not double-count or fail.
	body := `{"ids":[` + strconv.FormatInt(ids[0], 10) + `,` + strconv.FormatInt(ids[1], 10) + `,` +
		strconv.FormatInt(ids[0], 10) + `],"action":"permanent"}`
	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/bans/bulk", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("bulk promote = %d: %s", rec.Code, rec.Body.String())
	}
	var result struct {
		Updated int `json:"updated"`
		Skipped int `json:"skipped"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Updated != 2 || result.Skipped != 0 {
		t.Fatalf("bulk promote = %+v, want 2 updated", result)
	}

	list := authed(t, srv, token, csrf, http.MethodGet, "/api/bans", "")
	var active struct {
		Bans []struct {
			CIDR      string `json:"cidr"`
			Permanent bool   `json:"permanent"`
		} `json:"bans"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &active); err != nil {
		t.Fatal(err)
	}
	if len(active.Bans) != 2 {
		t.Fatalf("bans after promote = %d, want 2", len(active.Bans))
	}
	for _, b := range active.Bans {
		if !b.Permanent {
			t.Fatalf("%s was not promoted", b.CIDR)
		}
	}

	// Promoting an already-permanent row is a no-op, not an error.
	again := authed(t, srv, token, csrf, http.MethodPost, "/api/bans/bulk",
		`{"ids":[`+strconv.FormatInt(ids[0], 10)+`],"action":"permanent"}`)
	if again.Code != http.StatusOK {
		t.Fatalf("repeat promote = %d: %s", again.Code, again.Body.String())
	}
	if err := json.Unmarshal(again.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Updated != 0 || result.Skipped != 1 {
		t.Fatalf("repeat promote = %+v, want 0 updated and 1 skipped", result)
	}

	remove := `{"ids":[` + strconv.FormatInt(ids[0], 10) + `,` + strconv.FormatInt(ids[1], 10) + `],"action":"remove"}`
	rec = authed(t, srv, token, csrf, http.MethodPost, "/api/bans/bulk", remove)
	if rec.Code != http.StatusOK {
		t.Fatalf("bulk remove = %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Updated != 2 {
		t.Fatalf("bulk remove = %+v, want 2 updated", result)
	}
	list = authed(t, srv, token, csrf, http.MethodGet, "/api/bans", "")
	if err := json.Unmarshal(list.Body.Bytes(), &active); err != nil {
		t.Fatal(err)
	}
	if len(active.Bans) != 0 {
		t.Fatalf("bans after remove = %d, want 0", len(active.Bans))
	}
}

func TestBulkBansRejectsBadRequests(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	cases := map[string]string{
		"empty":       `{"ids":[],"action":"permanent"}`,
		"bad action":  `{"ids":[1],"action":"delete-everything"}`,
		"no payload":  `{}`,
		"missing ids": `{"action":"remove"}`,
	}
	for name, body := range cases {
		if rec := authed(t, srv, token, csrf, http.MethodPost, "/api/bans/bulk", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400: %s", name, rec.Code, rec.Body.String())
		}
	}
}
