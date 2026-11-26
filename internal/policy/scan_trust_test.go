package policy

import (
	"net/netip"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// A probe that presents a live run token is the node's own scanner. The decoy
// still refuses it, but it must not ban the address the node egresses from.
func TestScanTokenIsExemptFromTheDecoyBan(t *testing.T) {
	pol, st, bans := newEngine(t)
	pol.ScanTrust = func(token string) bool { return token == "run-token" }
	if _, err := st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyDecoy, Value: "/.env", Action: "block", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}

	trusted := pol.Screen(&Request{
		Addr: netip.MustParseAddr("203.0.113.9"), Method: "GET", Path: "/.env",
		ScanToken: "run-token",
	})
	if trusted.Action == "ban" {
		t.Fatalf("a scan's own probe would ban its source: %+v", trusted)
	}
	if trusted.Status != 403 {
		t.Fatalf("the decoy answered %d, want the refusal a probe must see", trusted.Status)
	}
	// The ban is written in a goroutine on the untrusted path only, so this is
	// a settled read rather than a race.
	if bans.Count() != 0 {
		t.Fatalf("the decoy wrote %d ban(s) for a trusted probe", bans.Count())
	}

	forged := pol.Screen(&Request{
		Addr: netip.MustParseAddr("203.0.113.10"), Method: "GET", Path: "/.env",
		ScanToken: "not-a-run-token",
	})
	if forged.Action != "ban" || forged.Stage != "decoy" {
		t.Fatalf("a token no run holds bypassed the decoy: %+v", forged)
	}
	waitBans(t, bans, 1)
}

// An address that was banned before the token existed would otherwise refuse
// every probe, so a trusted run has to be able to measure through the ban.
func TestScanTokenIsExemptFromAnExistingBan(t *testing.T) {
	pol, _, bans := newEngine(t)
	pol.ScanTrust = func(token string) bool { return token == "run-token" }
	if _, err := bans.Add("203.0.113.7", "decoy path requested: /.env", "decoy", "policy", 0); err != nil {
		t.Fatal(err)
	}

	trusted := pol.Screen(&Request{
		Addr: netip.MustParseAddr("203.0.113.7"), Method: "GET", Path: "/",
		ScanToken: "run-token",
	})
	if trusted.Action == "ban" {
		t.Fatalf("an existing ban refused the scan that caused it: %+v", trusted)
	}

	ordinary := pol.Screen(&Request{
		Addr: netip.MustParseAddr("203.0.113.7"), Method: "GET", Path: "/",
	})
	if ordinary.Action != "ban" || ordinary.Stage != "permanent-ban" {
		t.Fatalf("an ordinary request lost the permanent ban: %+v", ordinary)
	}
}

// The token lifts the decoy and ban rules, not the rate limit: a run has to be
// able to observe a 429, and the refusal must not write a ban for the address
// the node egresses from.
func TestScanTokenStillPaysTheRateLimit(t *testing.T) {
	pol, st, bans := newEngine(t)
	pol.ScanTrust = func(token string) bool { return token == "run-token" }
	if err := st.SetSetting("dos_rps", "1"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("dos_burst", "1"); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}

	probe := func() *Request {
		return &Request{
			Addr: netip.MustParseAddr("203.0.113.11"), Method: "GET", Path: "/",
			ScanToken: "run-token",
		}
	}
	if first := pol.Screen(probe()); first.Action != "allow" {
		t.Fatalf("first trusted probe = %+v, want the burst to admit it", first)
	}
	second := pol.Screen(probe())
	if second.Stage != "dos" || second.Status != 429 {
		t.Fatalf("the scan token was exempt from the rate limit: %+v", second)
	}
	if bans.Count() != 0 {
		t.Fatalf("a rate-limit refusal from the scanner wrote %d ban(s)", bans.Count())
	}
}

// The decoy ban is recorded asynchronously, so the count is only final once the
// row appears.
func waitBans(t *testing.T, bans interface{ Count() int }, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if bans.Count() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("bans = %d, want %d", bans.Count(), want)
}
