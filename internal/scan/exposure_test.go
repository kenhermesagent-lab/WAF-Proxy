package scan

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// newExposureRun serves /.env from the application and answers the published
// path with wanStatus. Every other path is a 404, so only the exposure stage
// has anything to say.
func newExposureRun(t *testing.T, wanStatus int, deny []string) (Target, *Runner) {
	t.Helper()
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			_, _ = io.WriteString(w, "DB_PASSWORD=hunter2")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(app.Close)
	wan := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.WriteHeader(wanStatus)
			if wanStatus == http.StatusOK {
				_, _ = io.WriteString(w, "DB_PASSWORD=hunter2")
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(wan.Close)
	appURL, err := url.Parse(app.URL)
	if err != nil {
		t.Fatal(err)
	}
	wanURL, err := url.Parse(wan.URL)
	if err != nil {
		t.Fatal(err)
	}
	target := Target{
		Proxy:    model.Proxy{ID: 1, Hostname: "app.example.com", Enabled: true, DenyPaths: deny},
		WAN:      Endpoint{URL: wanURL, Host: "app.example.com"},
		Upstream: Endpoint{URL: appURL, Host: "app.example.com"},
	}
	return target, NewRunner(target.WAN, target.Upstream, 0)
}

func exposureFindingFor(findings []model.ScanFinding, key string) *model.ScanFinding {
	for i := range findings {
		if findings[i].Key == key {
			return &findings[i]
		}
	}
	return nil
}

// A blocked path is still a finding while nothing but a blanket rule covers
// it: the file is still there.
func TestBlockedExposureIsAFindingWithoutAControl(t *testing.T) {
	target, runner := newExposureRun(t, http.StatusForbidden, nil)
	_, findings := runner.RunBackend(context.Background(), target, Intel{})
	f := exposureFindingFor(findings, "exposure:/.env")
	if f == nil {
		t.Fatalf("findings = %+v, want the blocked exposure reported", findings)
	}
	// Refused at the published path but still served: covered, not patched.
	if !f.Covered {
		t.Fatalf("finding = %+v, want it marked covered", f)
	}
}

// Once the site's own control refuses the path, the rerun has proved the
// exposure closed and must not keep reporting it.
func TestControlledExposureIsNotAFinding(t *testing.T) {
	target, runner := newExposureRun(t, http.StatusForbidden, []string{"/.env"})
	rows, findings := runner.RunBackend(context.Background(), target, Intel{})
	if f := exposureFindingFor(findings, "exposure:/.env"); f != nil {
		t.Fatalf("the controlled path is still a finding: %+v", f)
	}
	if !ExposureClosed(rows, "/.env") {
		t.Fatalf("evidence = %+v, want it to prove /.env closed", rows)
	}
}

// The control is only words if the published path still serves the file. A
// reachable path stays a high finding, and its evidence proves nothing.
func TestControlThatDoesNotRefuseIsStillAFinding(t *testing.T) {
	target, runner := newExposureRun(t, http.StatusOK, []string{"/.env"})
	rows, findings := runner.RunBackend(context.Background(), target, Intel{})
	f := exposureFindingFor(findings, "exposure:/.env")
	if f == nil || f.Severity != SeverityHigh {
		t.Fatalf("findings = %+v, want the reachable path reported high", findings)
	}
	if f.Covered {
		t.Fatalf("finding = %+v, want nothing called covered while the path is served", f)
	}
	if ExposureClosed(rows, "/.env") {
		t.Fatalf("evidence = %+v, want no proof while the path is served", rows)
	}
}
