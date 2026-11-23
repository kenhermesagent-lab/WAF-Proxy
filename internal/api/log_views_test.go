package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// secondBrowser signs a fresh account in on its own session, so requests carry
// a different cookie from the first browser's.
func secondBrowser(t *testing.T, st *store.Store, username string, roleID int64) (string, string) {
	t.Helper()
	hash, err := auth.HashPassword("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := st.CreateUserWithRole(username, hash, "", "", false, roleID)
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

func listLogViews(t *testing.T, srv *Server, token string) []model.LogView {
	t.Helper()
	rec := getJSON(t, srv, token, "/api/log-views")
	if rec.Code != http.StatusOK {
		t.Fatalf("list views status = %d: %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Views []model.LogView `json:"views"`
	}
	decodeJSON(t, rec, &list)
	return list.Views
}

func TestLogViewsAreSharedBetweenBrowsers(t *testing.T) {
	srv, st, admin, adminCSRF := newObservabilityServer(t)

	// The first browser saves a view.
	if rec := sendJSON(t, srv, http.MethodPut, admin, adminCSRF, "/api/log-views/Port%20scans", `{"query":"stage=waf&blocked=1"}`); rec.Code != http.StatusOK {
		t.Fatalf("save view status = %d: %s", rec.Code, rec.Body.String())
	}

	// A second browser, signed in separately, loads the same view.
	other, otherCSRF := secondBrowser(t, st, "second-admin", st.AdminRoleID())
	views := listLogViews(t, srv, other)
	if len(views) != 1 || views[0].Name != "Port scans" || views[0].Query != "stage=waf&blocked=1" {
		t.Fatalf("second browser sees %+v", views)
	}
	if views[0].UpdatedBy != "admin" {
		t.Fatalf("updated_by = %q, want the account that saved it", views[0].UpdatedBy)
	}

	// Saving the name again replaces its filters instead of adding a second row,
	// and the first browser sees the refined view.
	if rec := sendJSON(t, srv, http.MethodPut, other, otherCSRF, "/api/log-views/Port%20scans", `{"query":"stage=waf"}`); rec.Code != http.StatusOK {
		t.Fatalf("resave status = %d: %s", rec.Code, rec.Body.String())
	}
	views = listLogViews(t, srv, admin)
	if len(views) != 1 || views[0].Query != "stage=waf" || views[0].UpdatedBy != "second-admin" {
		t.Fatalf("after resave the first browser sees %+v", views)
	}

	// The viewer role reads the shared list but cannot change it.
	roles, err := st.ListRoles()
	if err != nil {
		t.Fatal(err)
	}
	var viewerID int64
	for _, role := range roles {
		if role.Name == "Viewer" {
			viewerID = role.ID
		}
	}
	if viewerID == 0 {
		t.Fatal("no Viewer role")
	}
	viewer, viewerCSRF := secondBrowser(t, st, "watcher", viewerID)
	if got := listLogViews(t, srv, viewer); len(got) != 1 {
		t.Fatalf("viewer sees %+v", got)
	}
	if rec := sendJSON(t, srv, http.MethodPut, viewer, viewerCSRF, "/api/log-views/Port%20scans", `{"query":"stage=waf"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer save status = %d, want 403", rec.Code)
	}
	if rec := sendJSON(t, srv, http.MethodDelete, viewer, viewerCSRF, "/api/log-views/Port%20scans", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer delete status = %d, want 403", rec.Code)
	}

	// Deleting from the second browser removes it for everyone.
	if rec := sendJSON(t, srv, http.MethodDelete, other, otherCSRF, "/api/log-views/Port%20scans", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d: %s", rec.Code, rec.Body.String())
	}
	if got := listLogViews(t, srv, admin); len(got) != 0 {
		t.Fatalf("views after delete = %+v", got)
	}
	// Deleting it again is the caller's end state, not an error.
	if rec := sendJSON(t, srv, http.MethodDelete, other, otherCSRF, "/api/log-views/Port%20scans", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("second delete status = %d", rec.Code)
	}
}

func TestLogViewNameIsRequired(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	if rec := sendJSON(t, srv, http.MethodPut, token, csrf, "/api/log-views/%20", `{"query":"stage=waf"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("blank name status = %d, want 400", rec.Code)
	}
	long := strings.Repeat("a", 65)
	if rec := sendJSON(t, srv, http.MethodPut, token, csrf, "/api/log-views/"+long, `{"query":"stage=waf"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("long name status = %d, want 400", rec.Code)
	}
}
