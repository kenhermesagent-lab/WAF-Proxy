package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/botguard"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/gate"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/policy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/proxy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

// newSettingsServer is the observability fixture plus the policy and proxy
// engines a settings write reloads. The plain fixture has neither, so every
// settings test so far only ever read them.
func newSettingsServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	srv, st, token, csrf := newObservabilityServer(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pol, err := policy.New(st, srv.bans, nil, nil, waf.NewSet(nil, log), log)
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(proxy.Deps{
		Store:   st,
		Policy:  pol,
		Gate:    gate.New(st, srv.box, srv.bans, log),
		Bots:    botguard.New([]byte("settings test key"), srv.bans, st, log),
		Bans:    srv.bans,
		Metrics: srv.metrics,
		Log:     log,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.policy, srv.proxy = pol, px
	// The plain fixture leaves GeoIP nil, and the settings read reports it.
	srv.geo = geoip.Open(t.TempDir())
	return srv, token, csrf
}

func TestSettingsWriteSavesNormalizationMode(t *testing.T) {
	srv, token, csrf := newSettingsServer(t)

	rec := authed(t, srv, token, csrf, http.MethodPut, "/api/settings", `{"normalization_mode":"block"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/settings = %d: %s", rec.Code, rec.Body.String())
	}
	if got := srv.policy.CurrentSettings().NormalizationMode; got != "block" {
		t.Fatalf("the policy engine reads %q after the save, want block", got)
	}

	rec = authed(t, srv, token, csrf, http.MethodGet, "/api/settings", "")
	var read map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &read); err != nil {
		t.Fatal(err)
	}
	if read["normalization_mode"] != "block" {
		t.Fatalf("read back %q, want block", read["normalization_mode"])
	}

	// An unknown value is refused, and the refusal leaves the saved value alone.
	rec = authed(t, srv, token, csrf, http.MethodPut, "/api/settings", `{"normalization_mode":"sometimes"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT with an unknown mode = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if got := srv.policy.CurrentSettings().NormalizationMode; got != "block" {
		t.Fatalf("the refused save changed the mode to %q", got)
	}
}
