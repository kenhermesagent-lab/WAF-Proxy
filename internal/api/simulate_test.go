package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/policy"
)

func simulate(t *testing.T, srv *Server, token, csrf, body string) (int, policy.SimResult) {
	t.Helper()
	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/simulate", body)
	var out policy.SimResult
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode simulation %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, out
}

func TestSimulateEndpoint(t *testing.T) {
	srv, token, csrf := newSettingsServer(t)
	st := srv.st
	profiles, err := st.ListProfiles()
	if err != nil || len(profiles) == 0 {
		t.Fatalf("profiles: %v", err)
	}
	prof := profiles[0]
	id, err := st.CreateProxy(&model.Proxy{
		Hostname: "sim.example.com", Enabled: true, ProfileID: &prof.ID, WAFMode: "block",
	})
	if err != nil {
		t.Fatal(err)
	}

	code, res := simulate(t, srv, token, csrf, fmt.Sprintf(`{"proxy_id":%d,"method":"GET","path":"/"}`, id))
	if code != http.StatusOK {
		t.Fatalf("allowed simulation = %d", code)
	}
	if res.Verdict.Action != "allow" {
		t.Fatalf("verdict = %+v, want allow", res.Verdict)
	}
	if last := res.Stages[len(res.Stages)-1]; last.Stage != "route" {
		t.Fatalf("last stage = %+v, want route selection", last)
	}

	code, res = simulate(t, srv, token, csrf,
		fmt.Sprintf(`{"proxy_id":%d,"method":"GET","path":"/search","query":"q=1%%27+OR+%%271%%27%%3D%%271"}`, id))
	if code != http.StatusOK {
		t.Fatalf("blocked simulation = %d", code)
	}
	if res.Verdict.Action != "block" || res.Verdict.Stage != "waf" {
		t.Fatalf("verdict = %+v, want a WAF block", res.Verdict)
	}
	if len(res.Matches) == 0 {
		t.Fatal("a blocked simulation must list the rules that matched")
	}
	if res.Exception == nil || res.Exception.ProfileID != prof.ID {
		t.Fatalf("exception = %+v, want profile %d", res.Exception, prof.ID)
	}

	if code, _ := simulate(t, srv, token, csrf, `{"proxy_id":9999,"path":"/"}`); code != http.StatusNotFound {
		t.Fatalf("unknown proxy = %d, want 404", code)
	}

	headers := map[string]string{}
	for i := 0; i < simMaxHeaders+1; i++ {
		headers["X-Test-"+strconv.Itoa(i)] = "v"
	}
	head, _ := json.Marshal(headers)
	code, _ = simulate(t, srv, token, csrf, fmt.Sprintf(`{"proxy_id":%d,"path":"/","headers":%s}`, id, head))
	if code != http.StatusBadRequest {
		t.Fatalf("too many headers = %d, want 400", code)
	}
}

// The body is cut at the profile limit and the response says so.
func TestSimulateTruncatesTheBody(t *testing.T) {
	srv, token, csrf := newSettingsServer(t)
	// A small limit keeps the simulated body small too; the default is large
	// enough that the request itself would exceed the API's own body ceiling.
	if err := srv.st.SetSetting("max_body", "4096"); err != nil {
		t.Fatal(err)
	}
	if err := srv.policy.Reload(); err != nil {
		t.Fatal(err)
	}
	id, err := srv.st.CreateProxy(&model.Proxy{Hostname: "sim-body.example.com", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("a", int(srv.policy.MaxBody(nil))+10)
	code, res := simulate(t, srv, token, csrf,
		fmt.Sprintf(`{"proxy_id":%d,"method":"POST","path":"/","body":%q}`, id, body))
	if code != http.StatusOK || !res.Truncated {
		t.Fatalf("status = %d, truncated = %v, want a truncated 200", code, res.Truncated)
	}
}
