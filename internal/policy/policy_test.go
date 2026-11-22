package policy

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/intel"
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

func screenHost(pol *Engine, proxy *model.Proxy, addr string) model.Verdict {
	return pol.Screen(&Request{
		Proxy:  proxy,
		Addr:   netip.MustParseAddr(addr),
		Method: "GET",
		Path:   "/",
	})
}

// A profile allow list narrows one host to the addresses it names, while the
// global list keeps working for every other host.
func TestAccessProfileAllowListNarrowsOneHost(t *testing.T) {
	pol, st, _ := newEngine(t)
	listID, err := st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyIPWhitelist, Value: "203.0.113.5",
		Action: "allow", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyIPWhitelist, Value: "198.51.100.0/24",
		Action: "allow", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	prof := &model.AccessProfile{Name: "office only", Rules: []model.AccessRule{{PolicyID: listID, Role: model.AccessRoleAllow}}}
	if err := st.CreateAccessProfile(prof); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}
	host := &model.Proxy{ID: 7, AccessProfileID: &prof.ID}
	if v := screenHost(pol, host, "203.0.113.5"); v.Action != "allow" {
		t.Fatalf("an address on the profile allow list was refused: %+v", v)
	}
	if v := screenHost(pol, host, "198.51.100.7"); v.Action != "block" || v.Stage != "profile-allow" {
		t.Fatalf("an address outside the profile allow list reached the host: %+v", v)
	}
	// The other host has no profile, so the global allow list still applies.
	if v := screenHost(pol, &model.Proxy{ID: 8}, "198.51.100.7"); v.Action != "allow" {
		t.Fatalf("a global allow list stopped working without a profile: %+v", v)
	}
}

// A profile deny list wins over a global allow list that names the address.
func TestAccessProfileDenyBeatsGlobalAllow(t *testing.T) {
	pol, st, _ := newEngine(t)
	if _, err := st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyIPWhitelist, Value: "203.0.113.0/24",
		Action: "allow", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	denyID, err := st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyIPWhitelist, Value: "203.0.113.9",
		Action: "allow", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	prof := &model.AccessProfile{Name: "no bad host", Rules: []model.AccessRule{{PolicyID: denyID, Role: model.AccessRoleDeny}}}
	if err := st.CreateAccessProfile(prof); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}
	host := &model.Proxy{ID: 9, AccessProfileID: &prof.ID}
	if v := screenHost(pol, host, "203.0.113.9"); v.Action != "block" || v.Stage != "profile-block" {
		t.Fatalf("a profile block list was ignored: %+v", v)
	}
	if v := screenHost(pol, host, "203.0.113.10"); v.Action != "allow" {
		t.Fatalf("the rest of the allowed prefix was refused: %+v", v)
	}
}

// A permanent ban rolled into a local threat list must stay absolute: an address
// on a global allow list is still refused while it is on that list.
func TestRolledUpPermanentBanBeatsTheAllowList(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	path := filepath.Join(t.TempDir(), "permanent-bans.txt")
	if err := os.WriteFile(path, []byte("203.0.113.9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	feedID, err := st.CreateFeed(&model.Feed{
		Name: "Permanent bans (rolled up)", Action: "block", IntervalS: 3600, Enabled: true,
		Local: true, AlwaysBlock: true, Filename: "permanent-bans.txt", LocalPath: path,
	})
	if err != nil {
		t.Fatal(err)
	}
	feeds := intel.New(st, log, 0)
	feeds.Refresh(context.Background(), feedID)

	bans, err := ban.New(st, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := New(st, bans, feeds, nil, waf.NewSet(nil, log), log)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyIPWhitelist, Value: "203.0.113.0/24",
		Action: "allow", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}

	if v := screen(pol, "203.0.113.9", "/"); v.Action != "block" || v.Stage != "permanent-ban-list" {
		t.Fatalf("a rolled-up permanent ban was lifted by the allow list: %+v", v)
	}
	if v := screen(pol, "203.0.113.10", "/"); v.Action != "allow" {
		t.Fatalf("the rest of the allowed prefix was refused: %+v", v)
	}
}
