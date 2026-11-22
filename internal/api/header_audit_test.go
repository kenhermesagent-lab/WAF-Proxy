package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func profileWith(frame, hsts, csp string, hstsOn bool) *model.ProtectionProfile {
	return &model.ProtectionProfile{FrameOptions: frame, HSTS: hstsOn, CSP: csp}
}

func checkFor(t *testing.T, checks []headerCheck, setting string) headerCheck {
	t.Helper()
	for _, c := range checks {
		if c.Setting == setting {
			return c
		}
	}
	t.Fatalf("no check for %q", setting)
	return headerCheck{}
}

func TestAuditWarnsWhenOffDeletesApplicationHeader(t *testing.T) {
	h := http.Header{}
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	h.Set("X-Content-Type-Options", "nosniff")
	checks := assessHeaders(h, profileWith("off", "", "", false))

	frame := checkFor(t, checks, "frame_options")
	if frame.Verdict != "at-risk" || !strings.Contains(frame.Advice, "deletes") {
		t.Fatalf("frame check = %+v, want at-risk warning", frame)
	}
	if hsts := checkFor(t, checks, "hsts"); hsts.Verdict != "covered" {
		t.Fatalf("hsts check = %+v, want covered", hsts)
	}
	if csp := checkFor(t, checks, "csp"); csp.Verdict != "covered" {
		t.Fatalf("csp check = %+v, want covered", csp)
	}
	if nosniff := checkFor(t, checks, "nosniff"); nosniff.Verdict != "covered" {
		t.Fatalf("nosniff check = %+v, want covered", nosniff)
	}
}

func TestAuditReportsGapsOnABareBackend(t *testing.T) {
	checks := assessHeaders(http.Header{}, profileWith("off", "", "", false))
	for _, c := range checks {
		if c.Verdict != "gap" {
			t.Errorf("%s on a bare backend = %s, want gap", c.Setting, c.Verdict)
		}
	}
}

func TestAuditSeesCSPFrameAncestors(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Security-Policy", "frame-ancestors 'self'")
	frame := checkFor(t, assessHeaders(h, profileWith("deny", "", "", false)), "frame_options")
	if frame.Verdict != "compatible" {
		t.Fatalf("frame check = %+v, want compatible", frame)
	}
}

func TestProbeTargetRejectsUnsupportedSchemes(t *testing.T) {
	if _, err := probeTarget("ftp://backend:21"); err == nil {
		t.Fatal("ftp upstream accepted")
	}
	u, err := probeTarget("https://backend:8443/api")
	if err != nil {
		t.Fatal(err)
	}
	if u.Path != "/" || u.Host != "backend:8443" {
		t.Fatalf("probe target = %s, want the root of the backend", u)
	}

}

func TestAuditWarnsWhenProfileRelaxesDeny(t *testing.T) {
	h := http.Header{}
	h.Set("X-Frame-Options", "DENY")
	frame := checkFor(t, assessHeaders(h, profileWith("sameorigin", "", "", false)), "frame_options")
	if frame.Verdict != "at-risk" || !strings.Contains(frame.Advice, "SAMEORIGIN") {
		t.Fatalf("frame check = %+v, want a warning that SAMEORIGIN is weaker than DENY", frame)
	}
}
