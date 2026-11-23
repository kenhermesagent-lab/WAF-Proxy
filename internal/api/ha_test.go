package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ha"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

type fakeHA struct {
	pairs, joins, syncs, failovers, failbacks, unpairs, notifies int
	max                                                          int
	failoverErr                                                  error
}

func (f *fakeHA) Pair(context.Context) (string, error) { f.pairs++; return "WAF-AAAA-BBBB", nil }
func (f *fakeHA) Join(context.Context, string, string, string) error {
	f.joins++
	return nil
}
func (f *fakeHA) Sync(context.Context) (ha.SyncResult, error) {
	f.syncs++
	return ha.SyncResult{}, nil
}
func (f *fakeHA) Failover(context.Context, ha.MoveOptions) (ha.Result, error) {
	f.failovers++
	return ha.Result{Epoch: 10}, f.failoverErr
}
func (f *fakeHA) Failback(context.Context, ha.MoveOptions) (ha.Result, error) {
	f.failbacks++
	return ha.Result{Epoch: 10}, nil
}
func (f *fakeHA) Unpair(context.Context) error { f.unpairs++; return nil }
func (f *fakeHA) Notify(context.Context, string) (ha.Result, error) {
	f.notifies++
	return ha.Result{}, nil
}
func (f *fakeHA) MaxFailovers() int           { return f.max }
func (f *fakeHA) SetMaxFailovers(n int) error { f.max = n; return nil }

const haTestPassword = "a sufficiently long password"

func haServer(t *testing.T) (*Server, *store.Store, *fakeHA, string, string) {
	t.Helper()
	srv, st, token, csrf := newObservabilityServer(t)
	srv.cfg.HAEnabled = true
	srv.SetHAStatus(func() HAStatus {
		return HAStatus{Enabled: true, Paired: true, ClusterID: "cluster-1",
			Role: "active", State: "active", Serving: true, Epoch: 9,
			Peer: "10.0.0.11:9443", PeerFingerprint: "peer-fp"}
	})
	ops := &fakeHA{max: 3}
	srv.SetHAOps(ops)
	return srv, st, ops, token, csrf
}

// haUser creates a signed-in account whose only role is the given permissions.
func haUser(t *testing.T, st *store.Store, name string, permissions []string) (string, string) {
	t.Helper()
	role := &model.Role{Name: name, Permissions: permissions}
	if err := st.CreateRole(role); err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword(haTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := st.CreateUserWithRole(name, hash, "", "", false, role.ID)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := wfcrypto.RandomToken(32)
	csrf, _ := wfcrypto.RandomToken(24)
	if err := st.CreateSession(token, uid, csrf, "127.0.0.1", "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return token, csrf
}

func haCall(t *testing.T, srv *Server, token, csrf, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "gui.local"
	req.RemoteAddr = "127.0.0.1:5000"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestHARoutesFollowThePermissions(t *testing.T) {
	srv, st, ops, _, _ := haServer(t)

	viewer, viewerCSRF := haUser(t, st, "viewer", []string{"dashboard.read", "traffic.read"})
	if rec := haCall(t, srv, viewer, viewerCSRF, http.MethodGet, "/api/ha", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer GET /api/ha = %d, want 403", rec.Code)
	}

	reader, readerCSRF := haUser(t, st, "ha-reader", []string{"ha.read"})
	if rec := haCall(t, srv, reader, readerCSRF, http.MethodGet, "/api/ha", ""); rec.Code != http.StatusOK {
		t.Fatalf("ha.read GET /api/ha = %d: %s", rec.Code, rec.Body.String())
	}
	body := `{"cluster_id":"cluster-1","password":"` + haTestPassword + `"}`
	if rec := haCall(t, srv, reader, readerCSRF, http.MethodPost, "/api/ha/failover", body); rec.Code != http.StatusForbidden {
		t.Fatalf("ha.read POST failover = %d, want 403", rec.Code)
	}
	if ops.failovers != 0 {
		t.Fatal("a read-only role reached the move manager")
	}
}

func TestHAActionsNeedFreshCredentialsAndTheClusterID(t *testing.T) {
	srv, _, ops, token, csrf := haServer(t)

	if rec := haCall(t, srv, token, csrf, http.MethodPost, "/api/ha/failover", `{"cluster_id":"cluster-1"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("failover without a password = %d, want 401", rec.Code)
	}
	bad := `{"cluster_id":"cluster-1","password":"wrong password"}`
	if rec := haCall(t, srv, token, csrf, http.MethodPost, "/api/ha/failover", bad); rec.Code != http.StatusUnauthorized {
		t.Fatalf("failover with a wrong password = %d, want 401", rec.Code)
	}
	wrongCluster := `{"cluster_id":"other","password":"` + haTestPassword + `"}`
	if rec := haCall(t, srv, token, csrf, http.MethodPost, "/api/ha/failover", wrongCluster); rec.Code != http.StatusConflict {
		t.Fatalf("failover with the wrong cluster id = %d, want 409", rec.Code)
	}
	if ops.failovers != 0 {
		t.Fatal("a refused request reached the manager")
	}

	good := `{"cluster_id":"cluster-1","password":"` + haTestPassword + `","dry_run":true}`
	if rec := haCall(t, srv, token, csrf, http.MethodPost, "/api/ha/failover", good); rec.Code != http.StatusOK {
		t.Fatalf("failover = %d: %s", rec.Code, rec.Body.String())
	}
	if ops.failovers != 1 {
		t.Fatalf("failover calls = %d, want 1", ops.failovers)
	}
}

func TestHAActionsAreRefusedWhileDisabled(t *testing.T) {
	srv, _, ops, token, csrf := haServer(t)
	srv.cfg.HAEnabled = false
	srv.SetHAStatus(func() HAStatus {
		return HAStatus{Enabled: false, Role: "standalone", State: "standalone", Serving: true}
	})
	body := `{"cluster_id":"cluster-1","password":"` + haTestPassword + `"}`
	if rec := haCall(t, srv, token, csrf, http.MethodPost, "/api/ha/failover", body); rec.Code != http.StatusConflict {
		t.Fatalf("disabled failover = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if ops.failovers != 0 {
		t.Fatal("a disabled host reached the manager")
	}
	// The read route still answers, so the page can explain why HA is off.
	rec := haCall(t, srv, token, csrf, http.MethodGet, "/api/ha", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("disabled GET /api/ha = %d", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["enabled"] != false {
		t.Fatalf("disabled status = %+v", got)
	}
}

func TestHABlockedMoveCarriesTheCheck(t *testing.T) {
	srv, _, ops, token, csrf := haServer(t)
	ops.failoverErr = &ha.BlockedError{Check: ha.Check{Name: "lease", Detail: "no lease", Fix: "check the witness"}}
	body := `{"cluster_id":"cluster-1","password":"` + haTestPassword + `"}`
	rec := haCall(t, srv, token, csrf, http.MethodPost, "/api/ha/failover", body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("blocked failover = %d, want 409", rec.Code)
	}
	var got struct {
		Error string   `json:"error"`
		Check ha.Check `json:"check"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Check.Name != "lease" || got.Error == "" {
		t.Fatalf("blocked body = %+v", got)
	}
}

func TestHAConfigSavesTheFlapBudget(t *testing.T) {
	srv, st, ops, token, csrf := haServer(t)
	body := `{"max_failovers_per_hour":5,"password":"` + haTestPassword + `"}`
	if rec := haCall(t, srv, token, csrf, http.MethodPut, "/api/ha/config", body); rec.Code != http.StatusOK {
		t.Fatalf("config = %d: %s", rec.Code, rec.Body.String())
	}
	if ops.max != 5 {
		t.Fatalf("live budget = %d, want 5", ops.max)
	}
	if raw, err := st.GetSetting("ha_max_failovers_per_hour"); err != nil || raw != "5" {
		t.Fatalf("stored budget = %q, %v", raw, err)
	}
	if rec := haCall(t, srv, token, csrf, http.MethodPut, "/api/ha/config", `{"max_failovers_per_hour":0,"password":"`+haTestPassword+`"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid budget = %d, want 400", rec.Code)
	}
}

func TestHAEveryActionReachesTheBackend(t *testing.T) {
	srv, _, ops, token, csrf := haServer(t)
	pw := `"password":"` + haTestPassword + `"`
	cases := []struct {
		action string
		body   string
		calls  func() int
	}{
		{"pair", `{` + pw + `}`, func() int { return ops.pairs }},
		{"join", `{"address":"10.0.0.10:9443","fingerprint":"fp","code":"WAF-X",` + pw + `}`, func() int { return ops.joins }},
		{"sync", `{` + pw + `}`, func() int { return ops.syncs }},
		{"failback", `{` + pw + `}`, func() int { return ops.failbacks }},
		{"unpair", `{"cluster_id":"cluster-1",` + pw + `}`, func() int { return ops.unpairs }},
		{"notify", `{"role":"BACKUP",` + pw + `}`, func() int { return ops.notifies }},
	}
	for _, tc := range cases {
		rec := haCall(t, srv, token, csrf, http.MethodPost, "/api/ha/"+tc.action, tc.body)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s = %d: %s", tc.action, rec.Code, rec.Body.String())
		}
		if tc.calls() != 1 {
			t.Fatalf("%s never reached the backend", tc.action)
		}
	}
	if rec := haCall(t, srv, token, csrf, http.MethodPost, "/api/ha/notify", `{"role":"nonsense",`+pw+`}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown notify role = %d, want 400", rec.Code)
	}
}

func TestHAEventsRecordTheAction(t *testing.T) {
	srv, _, _, token, csrf := haServer(t)
	body := `{"cluster_id":"cluster-1","password":"` + haTestPassword + `"}`
	if rec := haCall(t, srv, token, csrf, http.MethodPost, "/api/ha/failover", body); rec.Code != http.StatusOK {
		t.Fatalf("failover = %d", rec.Code)
	}
	rec := haCall(t, srv, token, csrf, http.MethodGet, "/api/ha/events", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("events = %d", rec.Code)
	}
	var got struct {
		Events []HAEvent `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Events) != 1 || got.Events[0].Action != "failover" || !got.Events[0].OK {
		t.Fatalf("events = %+v", got.Events)
	}
}
