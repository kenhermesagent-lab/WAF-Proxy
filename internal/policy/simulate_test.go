package policy

import (
	"net/netip"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func site(t *testing.T, profileID *int64) *model.Proxy {
	t.Helper()
	return &model.Proxy{ID: 1, Hostname: "app.example.com", Enabled: true, ProfileID: profileID, WAFMode: "block"}
}

func TestSimulateReportsABanFirst(t *testing.T) {
	pol, _, bans := newEngine(t)
	ip := netip.MustParseAddr("203.0.113.7")
	if _, err := bans.Add(ip.String(), "port scan", "scan", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	res := pol.Simulate(SimRequest{Proxy: site(t, nil), Method: "GET", Path: "/", Addr: ip})
	if res.Verdict.Action != "ban" || res.Verdict.Stage != "temp-ban" {
		t.Fatalf("verdict = %+v, want a temporary ban", res.Verdict)
	}
	if len(res.Stages) != 1 || res.Stages[0].Verdict != "ban" || res.Stages[0].RuleIDs[0] != "203.0.113.7/32" {
		t.Fatalf("stages = %+v, want the ban alone", res.Stages)
	}
}

func TestSimulateNamesTheBlockingStage(t *testing.T) {
	pol, st, _ := newEngine(t)
	if _, err := st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyCountryBlacklist, Value: "RU", Action: "block", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}
	res := pol.Simulate(SimRequest{
		Proxy: site(t, nil), Method: "GET", Path: "/", Addr: netip.MustParseAddr("198.51.100.10"),
		Loc: geoip.Location{Country: "RU"},
	})
	if res.Verdict.Action != "block" || res.Verdict.Stage != "country-block" {
		t.Fatalf("verdict = %+v, want a country block", res.Verdict)
	}
	if res.Stages[0].Stage != "country-block" || res.Stages[0].RuleIDs[0] != "country:RU" {
		t.Fatalf("stages = %+v, want the country stage named", res.Stages)
	}
}

func TestSimulateListsEveryWAFRuleAndTheProfileBlastRadius(t *testing.T) {
	pol, st, _ := newEngine(t)
	profiles, err := st.ListProfiles()
	if err != nil || len(profiles) == 0 {
		t.Fatalf("profiles: %v (%d)", err, len(profiles))
	}
	prof := profiles[0]
	first, err := st.CreateProxy(&model.Proxy{Hostname: "one.example.com", Enabled: true, ProfileID: &prof.ID, WAFMode: "block"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateProxy(&model.Proxy{Hostname: "two.example.com", Enabled: true, ProfileID: &prof.ID, WAFMode: "block"}); err != nil {
		t.Fatal(err)
	}
	p, err := st.GetProxy(first)
	if err != nil {
		t.Fatal(err)
	}

	res := pol.Simulate(SimRequest{
		Proxy: p, Host: p.Hostname, Method: "GET", Path: "/search",
		Query: "q=%3Cscript%3Ealert(1)%3C/script%3E&id=1%27+OR+%271%27%3D%271",
		Addr:  netip.MustParseAddr("198.51.100.10"),
	})
	if res.Verdict.Action != "block" || res.Verdict.Stage != "waf" {
		t.Fatalf("verdict = %+v, want a WAF block", res.Verdict)
	}
	if len(res.Matches) < 2 {
		t.Fatalf("matches = %+v, want several WAF rules", res.Matches)
	}
	if res.Exception == nil {
		t.Fatal("a WAF block should offer the exception that stops it")
	}
	if res.Exception.ProfileID != prof.ID || strconv.Itoa(res.Exception.RuleID) != res.Verdict.Rule {
		t.Fatalf("exception = %+v, want profile %d and rule %s", res.Exception, prof.ID, res.Verdict.Rule)
	}
	if !reflect.DeepEqual(res.Exception.OtherHosts, []string{"two.example.com"}) {
		t.Fatalf("other hosts = %v, want the other proxy on the profile", res.Exception.OtherHosts)
	}
}

func TestSimulateAllowsCleanAndFlagsNormalization(t *testing.T) {
	pol, _, _ := newEngine(t)

	res := pol.Simulate(SimRequest{Proxy: site(t, nil), Method: "GET", Path: "/", Addr: netip.MustParseAddr("198.51.100.10")})
	if res.Verdict.Action != "allow" {
		t.Fatalf("clean request verdict = %+v, want allow", res.Verdict)
	}
	for _, s := range res.Stages {
		if s.Skipped == "" && s.Verdict == "block" {
			t.Fatalf("clean request blocked at %+v", s)
		}
	}

	res = pol.Simulate(SimRequest{
		Proxy: site(t, nil), Method: "GET", Path: "/item", Query: "id=1&id=2",
		Addr: netip.MustParseAddr("198.51.100.10"),
	})
	if res.Verdict.Action != "log" || res.Verdict.Rule != "900120" {
		t.Fatalf("duplicate parameter verdict = %+v, want a 900120 log", res.Verdict)
	}
}

// A simulation must not spend the client's rate budget.
func TestSimulateSkipsRateLimiting(t *testing.T) {
	pol, _, _ := newEngine(t)
	pol.settings.RPS, pol.settings.Burst = 1, 1
	for i := 0; i < 5; i++ {
		res := pol.Simulate(SimRequest{Proxy: site(t, nil), Method: "GET", Path: "/", Addr: netip.MustParseAddr("198.51.100.10")})
		if res.Verdict.Action != "allow" {
			t.Fatalf("simulation %d verdict = %+v; it spent the rate limit", i, res.Verdict)
		}
	}
}
