package api

import (
	"errors"
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
