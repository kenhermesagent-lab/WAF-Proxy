package policy

import (
	"net/netip"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func screenGeo(pol *Engine, proxy *model.Proxy, addr, country string) model.Verdict {
	return pol.Screen(&Request{
		Proxy:  proxy,
		Addr:   netip.MustParseAddr(addr),
		Method: "GET",
		Path:   "/",
		Loc:    geoip.Location{Country: country},
	})
}

// A named blocklist attached to an access profile refuses its addresses and
// countries for that host, and leaves every other host alone.
func TestAccessListBlocklistBlocksOneHost(t *testing.T) {
	pol, st, _ := newEngine(t)
	block := &model.AccessList{Kind: model.ListKindBlock, Name: "scanners", IPs: "198.51.100.0/24", Countries: "RU"}
	if err := st.CreateAccessList(block); err != nil {
		t.Fatal(err)
	}
	prof := &model.AccessProfile{Name: "public site", ListIDs: []int64{block.ID}}
	if err := st.CreateAccessProfile(prof); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}
	guarded := &model.Proxy{ID: 1, Hostname: "app.example.com", AccessProfileID: &prof.ID}
	open := &model.Proxy{ID: 2, Hostname: "other.example.com"}

	if v := screenHost(pol, guarded, "198.51.100.9"); v.Action != "block" || v.Stage != "profile-block" {
		t.Fatalf("address on the blocklist was allowed: %+v", v)
	}
	if v := screenGeo(pol, guarded, "203.0.113.9", "RU"); v.Action != "block" || v.Stage != "profile-block" {
		t.Fatalf("country on the blocklist was allowed: %+v", v)
	}
	if v := screenHost(pol, open, "198.51.100.9"); v.Action != "allow" {
		t.Fatalf("the blocklist leaked onto a host without the profile: %+v", v)
	}
}

// A whitelist is the site's allow list: only what it names gets through, and
// an attached blocklist still wins over it.
func TestAccessListWhitelistIsExclusive(t *testing.T) {
	pol, st, _ := newEngine(t)
	allow := &model.AccessList{Kind: model.ListKindAllow, Name: "office", IPs: "203.0.113.7", Countries: "DE"}
	block := &model.AccessList{Kind: model.ListKindBlock, Name: "bad office host", IPs: "203.0.113.7"}
	if err := st.CreateAccessList(allow); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAccessList(block); err != nil {
		t.Fatal(err)
	}
	prof := &model.AccessProfile{Name: "office only", ListIDs: []int64{allow.ID}}
	if err := st.CreateAccessProfile(prof); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}
	proxy := &model.Proxy{ID: 3, Hostname: "intranet.example.com", AccessProfileID: &prof.ID}

	if v := screenHost(pol, proxy, "203.0.113.7"); v.Action != "allow" {
		t.Fatalf("listed address was refused: %+v", v)
	}
	if v := screenGeo(pol, proxy, "198.51.100.20", "DE"); v.Action != "allow" {
		t.Fatalf("listed country was refused: %+v", v)
	}
	if v := screenGeo(pol, proxy, "198.51.100.20", "FR"); v.Action != "block" || v.Stage != "profile-allow" {
		t.Fatalf("unlisted country was allowed: %+v", v)
	}
	if v := screenHost(pol, proxy, "203.0.113.8"); v.Action != "block" || v.Stage != "profile-allow" {
		t.Fatalf("unlisted address was allowed: %+v", v)
	}

	// Attaching the same address to a blocklist for this profile must win: an
	// operator who blocks explicitly means it.
	prof.ListIDs = append(prof.ListIDs, block.ID)
	if err := st.UpdateAccessProfile(prof); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}
	if v := screenHost(pol, proxy, "203.0.113.7"); v.Action != "block" || v.Stage != "profile-block" {
		t.Fatalf("the blocklist did not override the whitelist: %+v", v)
	}
}
