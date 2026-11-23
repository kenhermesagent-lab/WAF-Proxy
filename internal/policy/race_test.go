package policy

import (
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

// A bundle install recompiles the WAF while requests are in flight, and the
// per-profile mode lookup has to keep answering during that reload.
func TestReloadWhileInspecting(t *testing.T) {
	pol, st, _ := newEngine(t)
	profile := model.Profile{
		Name: "race", Mode: "block", Paranoia: 1, Anomaly: 5,
		AllowedMethods: "GET,HEAD", MaxBody: 131072,
		BundleModes: map[string]string{"cve-2026-11": model.BundleLog},
	}
	if err := st.CreateProfile(&profile); err != nil {
		t.Fatal(err)
	}
	pol.wafs = waf.NewSet(nil, pol.log)
	pol.SetBundleRules(bundlePack)
	if err := pol.ReloadWAF(); err != nil {
		t.Fatal(err)
	}

	proxy := &model.Proxy{ID: 1, Hostname: "app.example", Enabled: true, ProfileID: &profile.ID}
	req := httptest.NewRequest("GET", "https://app.example/wp-login.php", nil)
	inspect := func() model.Verdict {
		v, _ := pol.Inspect(&Request{
			Proxy: proxy, Host: "app.example", Method: "GET", Path: "/wp-login.php",
			Addr: netip.MustParseAddr("203.0.113.9"), HTTP: req,
		})
		return v
	}

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
				switch v := inspect(); v.Action {
				case "allow", "log", "block":
				default:
					panic("unexpected verdict action " + v.Action)
				}
				if first {
					ready <- struct{}{}
					first = false
				}
			}
		}()
	}
	for i := 0; i < readers; i++ {
		<-ready
	}

	for i := 0; i < 20; i++ {
		mode := model.BundleLog
		if i%2 == 0 {
			mode = model.BundleBlock
		}
		profile.BundleModes = map[string]string{"cve-2026-11": mode}
		if err := st.UpdateProfile(&profile); err != nil {
			close(stop)
			wg.Wait()
			t.Fatal(err)
		}
		if err := pol.ReloadWAF(); err != nil {
			close(stop)
			wg.Wait()
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	close(stop)
	wg.Wait()

	if v := inspect(); v.Action != "log" {
		t.Fatalf("final verdict = %+v, want the stored log mode", v)
	}
}
