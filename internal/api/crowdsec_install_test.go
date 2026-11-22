package api

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	updatepkg "github.com/kenhermesagent-lab/waf-proxy-docker/internal/updates"
)

func TestParseCrowdSecInstallOutput(t *testing.T) {
	out := "crowdsec-install: creating the bouncer key\n" +
		"WAFPROXY_LAPI=http://127.0.0.1:8080/\n" +
		"WAFPROXY_KEY=AbCdEf0123456789AbCdEf0123456789\n" +
		"crowdsec-install: done\n"
	lapi, key := parseCrowdSecInstallOutput(out)
	if lapi != "http://127.0.0.1:8080" {
		t.Fatalf("lapi = %q, want the reported URL without a trailing slash", lapi)
	}
	if key != "AbCdEf0123456789AbCdEf0123456789" {
		t.Fatalf("key = %q, want the reported bouncer key", key)
	}
}

func TestParseConsoleStatus(t *testing.T) {
	// Shape of `cscli console status` on an accepted engine (crowdsec docs).
	accepted := " ╭─────────────────────┬───────────────────────────────╮\n" +
		" │ Console connection  │                               │\n" +
		" ├─────────────────────┼───────────────────────────────┤\n" +
		" │ Central API (CAPI)  │ ✅ authenticated              │\n" +
		" │ Enrolled            │ ✅ enrolled                   │\n" +
		" │ Plan                │ SECOPS                        │\n" +
		" ╰─────────────────────┴───────────────────────────────╯\n"
	if state, detail := consoleStatusFromRows(parseConsoleRows(accepted)); state != "enrolled" || !strings.Contains(detail, "enrolled") {
		t.Fatalf("state = %q, detail = %q; want enrolled", state, detail)
	}

	for _, pending := range []string{
		" │ Enrolled            │ ✗ not enrolled                │\n",
		" │ Enrolled            │ ✗ pending                     │\n",
		" │ Enrolled            │ ❌ not enrolled               │\n",
	} {
		if state, _ := consoleStatusFromRows(parseConsoleRows(pending)); state != "pending" {
			t.Errorf("%q reported %q, want pending", strings.TrimSpace(pending), state)
		}
	}

	// The console unreachable or an unknown engine prints only local options.
	for _, out := range []string{"", "No console options\n", " │ Enroll              │ enrolled │\n"} {
		if state, _ := consoleStatusFromRows(parseConsoleRows(out)); state != "unknown" {
			t.Errorf("%q reported %q, want unknown", out, state)
		}
	}
}

func TestConsoleRowsReportPlanAndDecisionManagement(t *testing.T) {
	out := " │ Console connection  │                                │\n" +
		" │ Central API (CAPI)  │ ✅ authenticated               │\n" +
		" │ Enrolled            │ ✅ enrolled                    │\n" +
		" │ Plan                │ SECOPS                         │\n" +
		" │ Decision management │ ✅ active                      │\n" +
		" │ PAPI subscriptions  │ blocklist, management          │\n"
	rows := parseConsoleRows(out)
	if state, _ := consoleStatusFromRows(rows); state != "enrolled" {
		t.Fatalf("state = %q, want enrolled", state)
	}
	if got := plainCell(rowValue(rows, "plan")); got != "SECOPS" {
		t.Errorf("plan = %q, want SECOPS", got)
	}
	if got := plainCell(rowValue(rows, "central api (capi)")); got != "authenticated" {
		t.Errorf("capi = %q, want authenticated", got)
	}
	if got := plainCell(rowValue(rows, "decision management")); got != "active" || !decisionRowActive(got) {
		t.Errorf("decision management = %q (active=%v), want active", got, decisionRowActive(got))
	}
	if got := plainCell(rowValue(rows, "papi subscriptions")); got != "blocklist, management" {
		t.Errorf("papi = %q, want the subscriptions", got)
	}
}

// A console that cannot stat /etc/crowdsec (the credential files are root-only)
// must still report what the engine says, not "not linked".
func TestConsoleInfoPrefersStatusOverUnreadableCredentials(t *testing.T) {
	rows := map[string]string{"enrolled": "✅ enrolled", "plan": "SECOPS", "decision management": "✅ active"}
	denied := errors.New("permission denied")
	info := consoleInfoFromRows(rows, denied)
	if info.State != "enrolled" {
		t.Fatalf("state = %q, want enrolled even though the stat was denied", info.State)
	}
	if !info.DecisionsActive || info.Plan != "SECOPS" {
		t.Fatalf("plan/decisions = %q/%v, want SECOPS and active", info.Plan, info.DecisionsActive)
	}

	// No table and no credentials really does mean not linked.
	if info := consoleInfoFromRows(map[string]string{}, fs.ErrNotExist); info.State != "none" {
		t.Fatalf("state = %q, want none without credentials", info.State)
	}
	// A denied stat without a table stays unknown rather than claiming not linked.
	if info := consoleInfoFromRows(map[string]string{}, denied); info.State != "unknown" {
		t.Fatalf("state = %q, want unknown when the credentials cannot be read", info.State)
	}
}

func TestDecisionRowInactiveIsNotActive(t *testing.T) {
	for _, v := range []string{"", "not active", "✗ inactive", "not included", "requires a SECOPS plan"} {
		if decisionRowActive(v) {
			t.Errorf("%q reported active, want inactive", v)
		}
	}
	if !decisionRowActive("✅ active") {
		t.Error("✅ active reported inactive, want active")
	}
}

func TestParseCrowdSecInstallOutputRejectsJunk(t *testing.T) {
	for _, out := range []string{
		"",
		"WAFPROXY_KEY=short\n",
		"WAFPROXY_KEY=has space in it and is long enough\n",
		"WAFPROXY_KEY=<script>alert(1)</script>\n",
	} {
		if _, key := parseCrowdSecInstallOutput(out); key != "" {
			t.Errorf("%q produced key %q, want none", out, key)
		}
	}
	// A non-http endpoint falls back to the stock native default.
	lapi, _ := parseCrowdSecInstallOutput("WAFPROXY_LAPI=file:///etc/passwd\nWAFPROXY_KEY=AbCdEf0123456789AbCdEf\n")
	if lapi != defaultCrowdSecLAPI {
		t.Errorf("lapi = %q, want the default", lapi)
	}
}

func TestParseConsoleEnrollError(t *testing.T) {
	out := "crowdsec-install: enrolling the engine in your CrowdSec console\n" +
		"WAFPROXY_CONSOLE_ERROR=API error: 403 invalid enrollment key\n" +
		"WAFPROXY_LAPI=http://127.0.0.1:8080\n" +
		"WAFPROXY_KEY=AbCdEf0123456789AbCdEf0123456789\n"
	if got := parseConsoleEnrollError(out); got != "API error: 403 invalid enrollment key" {
		t.Fatalf("enroll error = %q, want the reported reason", got)
	}
	if got := parseConsoleEnrollError("WAFPROXY_KEY=AbCdEf0123456789AbCdEf0123456789\n"); got != "" {
		t.Fatalf("enroll error = %q, want none on a successful install", got)
	}
}

// A container or a host without the helper must never offer the install button.
func TestCrowdSecInstallRefusedWithoutHostSupport(t *testing.T) {
	s := &Server{}
	got := s.crowdsecInstallStatus()
	if got.Supported {
		t.Fatal("install reported as supported without a host manager")
	}
	if got.Reason == "" {
		t.Fatal("refusal has no reason for the operator")
	}
}

func TestCrowdSecInstallDetection(t *testing.T) {
	oldLook, oldStat := csLookPath, csStat
	defer func() { csLookPath, csStat = oldLook, oldStat }()
	csLookPath = func(string) (string, error) { return "/usr/bin/cscli", nil }
	csStat = func(string) (os.FileInfo, error) { return nil, errors.New("not found") }

	s := &Server{}
	got := s.crowdsecInstallStatus()
	if !got.Installed {
		t.Fatal("cscli on PATH must count as installed")
	}
	if got.ConsoleEnrolled {
		t.Fatal("missing console credentials must not read as enrolled")
	}
}

// The bouncer key is sealed in the database and must never reach the browser,
// because the page polls this output continuously.
func TestRedactInstallOutput(t *testing.T) {
	out := redactInstallOutput("line one\nWAFPROXY_KEY=AbCdEf0123456789AbCdEf\nWAFPROXY_LAPI=http://127.0.0.1:8080\n")
	if strings.Contains(out, "AbCdEf0123456789AbCdEf") {
		t.Fatalf("install output leaked the bouncer key: %q", out)
	}
	if !strings.Contains(out, "WAFPROXY_LAPI=http://127.0.0.1:8080") {
		t.Fatalf("progress output was dropped: %q", out)
	}
}

func TestValidConsoleKey(t *testing.T) {
	good := []string{"abcdefghijklmnop", "AbC-123_456+789/xyz=", "0123456789abcdef0123456789abcdef"}
	for _, key := range good {
		if !updatepkg.ValidConsoleKey(key) {
			t.Errorf("%q rejected", key)
		}
	}
	bad := []string{"", "short", "has space and is long enough", "semi;colon;longenough", "$(id)"}
	for _, key := range bad {
		if updatepkg.ValidConsoleKey(key) {
			t.Errorf("%q accepted", key)
		}
	}
}
