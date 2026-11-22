package policy

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

func newEngine(t *testing.T) (*Engine, *store.Store, *ban.Engine) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bans, err := ban.New(st, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := New(st, bans, nil, nil, waf.NewSet(nil, log), log)
	if err != nil {
		t.Fatal(err)
	}
	return pol, st, bans
}

func screen(pol *Engine, addr, path string) model.Verdict {
	return pol.Screen(&Request{
		Addr:   netip.MustParseAddr(addr),
		Method: "GET",
		Path:   path,
	})
}

func TestWhitelistDoesNotBypassTemporaryBan(t *testing.T) {
	pol, st, bans := newEngine(t)
	if _, err := st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyIPWhitelist, Value: "203.0.113.0/24", Action: "allow", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := bans.Add("203.0.113.7", "port scan", "scan", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	v := screen(pol, "203.0.113.7", "/")
	if v.Action != "ban" || v.Stage != "temp-ban" {
		t.Fatalf("whitelisted address bypassed a temporary ban: %+v", v)
	}
}

func TestPermanentBanBeatsWhitelist(t *testing.T) {
	pol, st, bans := newEngine(t)
	if _, err := st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyIPWhitelist, Value: "203.0.113.7", Action: "allow", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := bans.Add("203.0.113.7", "decoy hit", "decoy", "test", 0); err != nil {
		t.Fatal(err)
	}
	v := screen(pol, "203.0.113.7", "/")
	if v.Action != "ban" || v.Stage != "permanent-ban" {
		t.Fatalf("permanent ban was not absolute: %+v", v)
	}
}

func TestCountryWhitelistWins(t *testing.T) {
	pol, st, _ := newEngine(t)
	for _, p := range []*model.Policy{
		{Scope: "global", Kind: model.PolicyCountryBlacklist, Value: "RU", Action: "block", Enabled: true},
		{Scope: "global", Kind: model.PolicyCountryWhitelist, Value: "RU", Action: "allow", Enabled: true},
	} {
		if _, err := st.CreatePolicy(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}
	v := pol.Screen(&Request{
		Addr: netip.MustParseAddr("198.51.100.10"), Method: "GET", Path: "/",
		Loc: geoip.Location{Country: "RU"},
	})
	if v.Action != "allow" || v.Stage != "whitelist" {
		t.Fatalf("country whitelist did not override the blacklist: %+v", v)
	}
}

func TestCountryAllowListBlocksOtherCountries(t *testing.T) {
	pol, st, _ := newEngine(t)
	if _, err := st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyCountryWhitelist, Value: "RU", Action: "allow", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}
	v := pol.Screen(&Request{
		Addr: netip.MustParseAddr("198.51.100.11"), Method: "GET", Path: "/",
		Loc: geoip.Location{Country: "US"},
	})
	if v.Action != "block" || v.Stage != "country-allow" {
		t.Fatalf("country outside the allow list was not blocked: %+v", v)
	}
	// An explicit IP whitelist still wins over the country allow list.
	if _, err := st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyIPWhitelist, Value: "198.51.100.11", Action: "allow", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}
	v = pol.Screen(&Request{
		Addr: netip.MustParseAddr("198.51.100.11"), Method: "GET", Path: "/",
		Loc: geoip.Location{Country: "US"},
	})
	if v.Action != "allow" || v.Stage != "whitelist" {
		t.Fatalf("IP whitelist did not override the country allow list: %+v", v)
	}
}

func TestDecoyBan(t *testing.T) {
	pol, _, _ := newEngine(t)
	v := screen(pol, "198.51.100.20", "/.env")
	if v.Action != "ban" || v.Stage != "decoy" {
		t.Fatalf("decoy path was not banned: %+v", v)
	}
}

func TestIPBlacklistBeatsTheAllowList(t *testing.T) {
	pol, st, _ := newEngine(t)
	for _, p := range []*model.Policy{
		{Scope: "global", Kind: model.PolicyIPWhitelist, Value: "203.0.113.0/24", Action: "allow", Enabled: true},
		{Scope: "global", Kind: model.PolicyIPBlacklist, Value: "203.0.113.9", Action: "block", Enabled: true},
	} {
		if _, err := st.CreatePolicy(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}
	if v := screen(pol, "203.0.113.9", "/"); v.Action != "block" || v.Stage != "ip-blacklist" {
		t.Fatalf("blocked address was allowed: %+v", v)
	}
	if v := screen(pol, "203.0.113.10", "/"); v.Action != "allow" {
		t.Fatalf("the rest of the allowed prefix was refused: %+v", v)
	}
}
