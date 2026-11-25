package gate

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// A scan account is a machine credential. It may open only the hostnames it was
// explicitly bound to, never the implicit "empty ACL means every gate user" that
// a human account gets.
func TestScanOnlyAccountBindsToTargetHosts(t *testing.T) {
	f := newGateFixture(t, "accounts")
	other := &model.Proxy{Hostname: "other.example.com", Enabled: true, GateMode: "accounts"}
	id, err := f.st.CreateProxy(other)
	if err != nil {
		t.Fatal(err)
	}
	other.ID = id

	const password = "scan-only-password-1"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := f.box.Seal(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.CreateScanGateUser("scanner", hash, sealed); err != nil {
		t.Fatal(err)
	}
	if err := f.st.AddGateACL(f.p.ID, "scanner"); err != nil {
		t.Fatal(err)
	}

	form := url.Values{"username": {"scanner"}, "password": {password}, "next": {"/"}}.Encode()
	// The bound host accepts the account.
	rec := f.post(t, form, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("bound host answered %d, want 303: %s", rec.Code, rec.Body.String())
	}
	if sessionCookie(rec) == nil {
		t.Fatal("the bound host accepted the sign-in without a session cookie")
	}

	// The unbound host refuses it with the same uniform failure as a wrong
	// password.
	r := httptest.NewRequest(http.MethodPost, "http://other.example.com"+LoginPath, strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	if !f.g.Handle(rec, r, other, netip.MustParseAddr(gateTestIP)) {
		t.Fatal("the gate did not handle the login post")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unbound host answered %d, want 401", rec.Code)
	}

	// The store hands the scanner account to a run only for a bound host.
	account, err := f.st.ScanGateUser(f.p.ID)
	if err != nil {
		t.Fatalf("the bound host has no scan account: %v", err)
	}
	if account.Username != "scanner" || account.ScanSecret == "" || !account.ScanOnly {
		t.Fatalf("scan account = %+v, want the sealed scanner row", account)
	}
	if _, err := f.st.ScanGateUser(other.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the unbound host resolved a scan account: %v", err)
	}
}
