package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// A PUT that names one setting must leave the rest of the record alone. These
// cover the handlers that used to write every field from the payload, where a
// partial request silently cleared the protection it did not mention.

func TestProtectionProfilePartialUpdateKeepsTheOtherHeaders(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/protection-profiles",
		`{"name":"Strict","force_https":true,"hsts":true,"hsts_subdomains":true,"nosniff":true,`+
			`"hide_server":true,"frame_options":"deny","referrer_policy":"no-referrer",`+
			`"csp":"default-src 'self'","permissions_policy":"geolocation=()"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create protection profile = %d: %s", rec.Code, rec.Body.String())
	}
	var created model.ProtectionProfile
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	path := "/api/protection-profiles/" + strconv.FormatInt(created.ID, 10)

	rec = authed(t, srv, token, csrf, http.MethodPut, path, `{"csp":"default-src 'none'"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT csp = %d: %s", rec.Code, rec.Body.String())
	}
	var got model.ProtectionProfile
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.CSP != "default-src 'none'" {
		t.Fatalf("csp = %q", got.CSP)
	}
	if !got.HSTS || !got.HSTSSubdomains || !got.NoSniff || !got.HideServer || !got.ForceHTTPS {
		t.Fatalf("a csp edit cleared the other switches: %+v", got)
	}
	if got.FrameOptions != "deny" || got.ReferrerPolicy != "no-referrer" || got.PermissionsPolicy != "geolocation=()" {
		t.Fatalf("a csp edit cleared the other headers: %+v", got)
	}

	// Naming the key is still how a switch is turned off.
	rec = authed(t, srv, token, csrf, http.MethodPut, path, `{"nosniff":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT nosniff = %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.NoSniff {
		t.Fatal("nosniff was not turned off")
	}
	if !got.HSTS || got.CSP != "default-src 'none'" {
		t.Fatalf("turning off nosniff cleared the rest: %+v", got)
	}
}

func TestAccessProfilePartialUpdateKeepsItsLists(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	if err := srv.st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/lists",
		`{"name":"Office","kind":"whitelist","ips":"10.0.0.0/8"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create list = %d: %s", rec.Code, rec.Body.String())
	}
	var list struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}

	rec = authed(t, srv, token, csrf, http.MethodPost, "/api/profiles", `{"name":"Staff WAF"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create waf profile = %d: %s", rec.Code, rec.Body.String())
	}
	var waf model.Profile
	if err := json.Unmarshal(rec.Body.Bytes(), &waf); err != nil {
		t.Fatal(err)
	}

	body := `{"name":"Staff","list_ids":[` + strconv.FormatInt(list.ID, 10) + `],"waf_profile_id":` + strconv.FormatInt(waf.ID, 10) + `}`
	rec = authed(t, srv, token, csrf, http.MethodPost, "/api/access-profiles", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create access profile = %d: %s", rec.Code, rec.Body.String())
	}
	var ap model.AccessProfile
	if err := json.Unmarshal(rec.Body.Bytes(), &ap); err != nil {
		t.Fatal(err)
	}
	if len(ap.ListIDs) != 1 || ap.WAFProfileID == nil {
		t.Fatalf("created profile is missing its references: %+v", ap)
	}
	path := "/api/access-profiles/" + strconv.FormatInt(ap.ID, 10)

	// Detaching the WAF profile must not empty the allow lists with it.
	rec = authed(t, srv, token, csrf, http.MethodPut, path, `{"waf_profile_id":null}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT waf_profile_id = %d: %s", rec.Code, rec.Body.String())
	}
	var got model.AccessProfile
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.WAFProfileID != nil {
		t.Fatal("waf_profile_id was not cleared")
	}
	if len(got.ListIDs) != 1 || got.ListIDs[0] != list.ID {
		t.Fatalf("a waf_profile_id edit emptied the lists: %+v", got)
	}

	// Naming list_ids is still how the lists are replaced.
	rec = authed(t, srv, token, csrf, http.MethodPut, path, `{"list_ids":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT list_ids = %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.ListIDs) != 0 {
		t.Fatalf("list_ids was not cleared: %+v", got)
	}
}

func TestAccessListPartialUpdateKeepsTheOtherField(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/lists",
		`{"name":"Blocked","kind":"blocklist","ips":"203.0.113.0/24","countries":"RU,CN"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create list = %d: %s", rec.Code, rec.Body.String())
	}
	var list struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	path := "/api/lists/" + strconv.FormatInt(list.ID, 10)

	rec = authed(t, srv, token, csrf, http.MethodPut, path, `{"ips":"198.51.100.0/24"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT ips = %d: %s", rec.Code, rec.Body.String())
	}
	var got model.AccessList
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.IPs != "198.51.100.0/24" {
		t.Fatalf("ips = %q", got.IPs)
	}
	if !strings.Contains(got.Countries, "RU") || !strings.Contains(got.Countries, "CN") {
		t.Fatalf("an ips edit cleared the countries: %q", got.Countries)
	}
	if got.Kind != "blocklist" || got.Name != "Blocked" {
		t.Fatalf("an ips edit changed the identity: %+v", got)
	}

	rec = authed(t, srv, token, csrf, http.MethodPut, path, `{"countries":""}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT countries = %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Countries != "" {
		t.Fatalf("countries was not cleared: %q", got.Countries)
	}
	if got.IPs != "198.51.100.0/24" {
		t.Fatalf("clearing countries cleared the addresses too: %q", got.IPs)
	}
}

func TestFeedPartialUpdateKeepsUrlAndAction(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/feeds",
		`{"name":"Abuse","url":"https://example.com/abuse.txt","action":"challenge","interval_s":900}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create feed = %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	path := "/api/feeds/" + strconv.FormatInt(created.ID, 10)

	if rec := authed(t, srv, token, csrf, http.MethodPut, path, `{"enabled":false}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT enabled = %d: %s", rec.Code, rec.Body.String())
	}
	stored, err := st.FeedByID(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Enabled {
		t.Fatal("the feed was not paused")
	}
	if stored.URL != "https://example.com/abuse.txt" || stored.Name != "Abuse" || stored.Action != "challenge" || stored.IntervalS != 900 {
		t.Fatalf("pausing the feed cleared the rest: %+v", stored)
	}
}

func TestPolicyToggleKeepsScopeAndValue(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if err := srv.st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/proxies",
		`{"hostname":"shop.example.com","upstreams":[{"url":"http://10.0.0.1:8080","enabled":true}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create proxy = %d: %s", rec.Code, rec.Body.String())
	}
	var proxy model.Proxy
	if err := json.Unmarshal(rec.Body.Bytes(), &proxy); err != nil {
		t.Fatal(err)
	}

	body := fmt.Sprintf(`{"scope":"proxy","proxy_id":%d,"kind":"country_blacklist","value":"RU","action":"block","note":"demo"}`,
		proxy.ID)
	rec = authed(t, srv, token, csrf, http.MethodPost, "/api/policies", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create policy = %d: %s", rec.Code, rec.Body.String())
	}
	var created model.Policy
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	path := "/api/policies/" + strconv.FormatInt(created.ID, 10)

	// Pausing a policy is the reason this exists: the toggle alone used to fail
	// on the empty kind, and had it passed it would have made the policy global.
	rec = authed(t, srv, token, csrf, http.MethodPut, path, `{"enabled":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT enabled = %d: %s", rec.Code, rec.Body.String())
	}
	stored, err := st.GetPolicy(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Enabled {
		t.Fatal("the policy was not paused")
	}
	if stored.Scope != "proxy" || stored.ProxyID == nil || *stored.ProxyID != proxy.ID {
		t.Fatalf("pausing the policy reset its scope: %+v", stored)
	}
	if stored.Kind != "country_blacklist" || stored.Value != "RU" || stored.Action != "block" || stored.Note != "demo" {
		t.Fatalf("pausing the policy cleared the rest: %+v", stored)
	}

	// A named key is still written, and still validated.
	rec = authed(t, srv, token, csrf, http.MethodPut, path, `{"value":"CN"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT value = %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Value != "CN" || stored.Scope != "proxy" || stored.Enabled {
		t.Fatalf("a value edit lost the rest: %+v", stored)
	}
	if rec := authed(t, srv, token, csrf, http.MethodPut, path, `{"value":""}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("an emptied value was accepted: %d: %s", rec.Code, rec.Body.String())
	}
}

// The proxy handler already merged by presence; this keeps it that way, since a
// hostname edit that emptied the upstream pool would take the site down.
func TestProxyUpdateKeepsUpstreamsWhenNotNamed(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if err := srv.st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/proxies",
		`{"hostname":"app.example.com","upstreams":[{"url":"http://10.0.0.1:8080","enabled":true},`+
			`{"url":"http://10.0.0.2:8080","enabled":true}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create proxy = %d: %s", rec.Code, rec.Body.String())
	}
	var created model.Proxy
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	path := "/api/proxies/" + strconv.FormatInt(created.ID, 10)

	if rec := authed(t, srv, token, csrf, http.MethodPut, path, `{"bot_level":"standard"}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT bot_level = %d: %s", rec.Code, rec.Body.String())
	}
	ups, err := st.ListUpstreams(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 2 {
		t.Fatalf("an unrelated edit left %d upstreams, want 2", len(ups))
	}

	// Naming the key is still how the pool is replaced.
	if rec := authed(t, srv, token, csrf, http.MethodPut, path, `{"upstreams":[{"url":"http://10.0.0.3:8080","enabled":true}]}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT upstreams = %d: %s", rec.Code, rec.Body.String())
	}
	ups, err = st.ListUpstreams(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 1 || ups[0].URL != "http://10.0.0.3:8080" {
		t.Fatalf("the named pool was not applied: %+v", ups)
	}
}
