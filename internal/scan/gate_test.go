package scan

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/gate"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// gatePageHTML is the challenge the gate serves for every path.
const gatePageHTML = `<!doctype html><html><body><form method="post" action="` + gate.LoginPath + `">` +
	`<input name="password" type="password"></form></body></html>`

// newGateRun starts a fake published host and returns the runner aimed at it.
func newGateRun(t *testing.T, mode string, handler http.HandlerFunc) (Target, *Runner) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	target := Target{
		Proxy:    model.Proxy{ID: 1, Hostname: "app.example.com", Enabled: true, GateMode: mode},
		WAN:      Endpoint{URL: u, Host: "app.example.com"},
		Upstream: Endpoint{URL: u, Host: "app.example.com"},
	}
	return target, NewRunner(target.WAN, target.Upstream, 0)
}

// challenge writes the gate's unauthenticated answer.
func challenge(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, gatePageHTML)
}

// passphraseGate answers like a gate in passphrase mode. Every failure that is
// not a cross-site post is counted, so a test can prove the failure budget.
func passphraseGate(failures *int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != gate.LoginPath {
			challenge(w)
			return
		}
		if r.Header.Get("Origin") != "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.PostFormValue("password") == "right-passphrase" {
			http.SetCookie(w, &http.Cookie{Name: gate.CookieName, Value: "fresh-session"})
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		atomic.AddInt32(failures, 1)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, gatePageHTML)
	}
}

// accountGate answers like an accounts-mode gate that never accepts a login.
func accountGate(logins *int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == gate.LoginPath {
			// The cross-origin check is a login post too, but it is refused
			// before credentials are read, so it is not a sign-in attempt.
			if logins != nil && r.Header.Get("Origin") == "" {
				atomic.AddInt32(logins, 1)
			}
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, gatePageHTML)
			return
		}
		challenge(w)
	}
}

func findRow(t *testing.T, rows []model.ScanEvidence, class string) model.ScanEvidence {
	t.Helper()
	for _, row := range rows {
		if row.Class == class {
			return row
		}
	}
	t.Fatalf("no %s evidence row in %d rows", class, len(rows))
	return model.ScanEvidence{}
}

// The suite may never cause a third credential failure: the ladder bans an
// address on the third in ten minutes, and a ban would take the operator's own
// site down for visitors.
func TestGateProbesCapAtTwoFailures(t *testing.T) {
	var failures int32
	target, runner := newGateRun(t, "passphrase", passphraseGate(&failures))

	rows := runner.RunGate(context.Background(), target, GateOptions{Pause: -1})
	if got := atomic.LoadInt32(&failures); got != 2 {
		t.Fatalf("credential failures = %d, want exactly 2", got)
	}
	if row := findRow(t, rows, "G6"); row.Verdict != string(Passed) {
		t.Fatalf("G6 = %q (%s), want passed", row.Verdict, row.Note)
	}
	if row := findRow(t, rows, "G7"); !strings.Contains(row.Note, "2 deliberate") {
		t.Fatalf("G7 does not report the two failures: %s", row.Note)
	}

	// A budget of one cannot produce a comparable pair, so nothing is sent.
	atomic.StoreInt32(&failures, 0)
	rows = runner.RunGate(context.Background(), target, GateOptions{Pause: -1, MaxFailures: 1})
	if got := atomic.LoadInt32(&failures); got != 0 {
		t.Fatalf("a one-failure budget sent %d failures, want 0", got)
	}
	row := findRow(t, rows, "G6")
	if row.Verdict != string(NotRun) || !strings.Contains(row.Note, "not tested") {
		t.Fatalf("G6 with a spent budget = %q (%s), want a not-tested row", row.Verdict, row.Note)
	}
}

// A forward-auth gate is not ours: the session probes are reported not
// applicable, and the suite never posts a login at it.
func TestGateProbesSkipInForwardAuthMode(t *testing.T) {
	var logins int32
	provider := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			atomic.AddInt32(&logins, 1)
		}
		w.Header().Set("Location", "https://idp.example/auth")
		w.WriteHeader(http.StatusFound)
	}
	target, runner := newGateRun(t, "forward_auth", provider)
	signedOut := false
	rows := runner.RunGate(context.Background(), target, GateOptions{
		Account: &GateAccount{Username: "scanner", Password: "scan-password-1"},
		Pause:   -1,
		SignOut: func(string) error { signedOut = true; return nil },
	})
	if got := atomic.LoadInt32(&logins); got != 0 {
		t.Fatalf("a forward-auth run posted %d login(s)", got)
	}
	if signedOut {
		t.Fatal("a forward-auth run tried to end a session it does not own")
	}
	for _, row := range rows {
		switch row.Class {
		case "G3", "G4", "G5", "G6", "G7", "G8", "G9", "G10", "G11", "G12":
			t.Errorf("%s ran against a forward-auth gate: %s", row.Class, row.Note)
		}
	}
	if row := findRow(t, rows, "G3-G12"); row.Verdict != string(NotApplicable) {
		t.Fatalf("the forward-auth exclusion = %q, want not-applicable", row.Verdict)
	}
	if row := findRow(t, rows, "F3"); row.Verdict != string(Passed) {
		t.Fatalf("F3 = %q (%s), want passed", row.Verdict, row.Note)
	}
	if row := findRow(t, rows, "F1"); row.Verdict != string(NotRun) || !strings.Contains(row.Note, "not tested") {
		t.Fatalf("F1 = %q (%s), want not tested until the provider is made unreachable", row.Verdict, row.Note)
	}
}

// Without the scan account the authenticated checks are not tested. Reporting
// them as passed would be a green gate result built on nothing.
func TestGateProbeReportsNotTestedWithoutAccount(t *testing.T) {
	var logins int32
	target, runner := newGateRun(t, "accounts", accountGate(&logins))
	rows := runner.RunGate(context.Background(), target, GateOptions{Pause: -1})

	for _, class := range []string{"G3", "G4", "G5", "G8", "G10"} {
		row := findRow(t, rows, class)
		if row.Verdict != string(NotRun) || !strings.Contains(row.Note, "not tested") {
			t.Errorf("%s without an account = %q (%s), want not tested", class, row.Verdict, row.Note)
		}
	}
	if got := atomic.LoadInt32(&logins); got != 0 {
		t.Fatalf("the suite posted %d login(s) without an account", got)
	}
	if row := findRow(t, rows, "G1"); row.Verdict != string(BlockedGate) {
		t.Fatalf("G1 = %q (%s), want blocked-gate", row.Verdict, row.Note)
	}
}

// The console is where administrators sign in. A scanner must not sign in
// there even when a target row points at it.
func TestGateProbeRefusesConsoleHostname(t *testing.T) {
	var requests int32
	target, runner := newGateRun(t, "accounts", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		challenge(w)
	})
	target.Proxy.Hostname = "console.example.com"

	rows := runner.RunGate(context.Background(), target, GateOptions{
		Account:     &GateAccount{Username: "scanner", Password: "scan-password-1"},
		ConsoleHost: "console.example.com",
	})
	if len(rows) != 1 {
		t.Fatalf("console target produced %d rows, want one refusal", len(rows))
	}
	if rows[0].Verdict != string(NotRun) || !strings.Contains(rows[0].Note, "console") {
		t.Fatalf("console refusal = %q (%s)", rows[0].Verdict, rows[0].Note)
	}
	if got := atomic.LoadInt32(&requests); got != 0 {
		t.Fatalf("the suite sent %d request(s) to the console", got)
	}
}
