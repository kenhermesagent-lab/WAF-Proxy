package waf

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func racePack(version string) []Bundle {
	return []Bundle{{Name: "cve-2026-11", Version: version, Rules: []BundleRule{{
		ID: 990417, Message: "template injection probe", Severity: "CRITICAL",
		Target: "REQUEST_URI", Operator: "@contains /wp-login.php",
	}}}}
}

// Installing a pack drops every compiled engine and rebuilds the fallback
// while requests are being served, so the set must be readable throughout.
func TestSetBundlesWhileInspecting(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	profile := model.Profile{ID: 1, Name: "web", Mode: "block", Paranoia: 1, Anomaly: 5, MaxBody: 131072}
	s := NewSet([]model.Profile{profile}, log)
	s.SetBundles(racePack("1"))

	id, unknown := int64(1), int64(99)
	req := httptest.NewRequest("GET", "https://app.example/wp-login.php", nil)
	addr := netip.MustParseAddr("203.0.113.9")

	const readers = 4
	stop := make(chan struct{})
	ready := make(chan struct{}, readers)
	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			first := true
			for {
				select {
				case <-stop:
					return
				default:
				}
				s.For(&id).InspectAll(req, nil, addr)
				s.For(nil).InspectAll(req, nil, addr)
				s.For(&unknown).InspectAll(req, nil, addr)
				if first {
					ready <- struct{}{}
					first = false
				}
			}
		}()
	}
	// Wait until every reader has inspected at least once, so the installs
	// below genuinely overlap the readers instead of running before them.
	for i := 0; i < readers; i++ {
		<-ready
	}
	for i := 0; i < 20; i++ {
		s.SetBundles(racePack("v" + strconv.Itoa(i)))
		s.Reload([]model.Profile{profile})
		time.Sleep(2 * time.Millisecond)
	}
	close(stop)
	wg.Wait()

	// The fallback engine must actually be the one these packs built, or the
	// loop above proves nothing.
	s.mu.RLock()
	installed := s.fallback.bundles[990417].version
	s.mu.RUnlock()
	if installed != "v19" {
		t.Fatalf("fallback engine holds pack %q, want v19", installed)
	}
}
