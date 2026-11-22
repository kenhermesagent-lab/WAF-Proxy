package preset

import (
	"net/netip"
	"strings"
	"testing"
)

func TestPresetsAreConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range All() {
		if p.ID == "" || p.Name == "" || p.Description == "" {
			t.Errorf("preset %+v is missing an id, name or description", p)
		}
		if seen[p.ID] {
			t.Errorf("preset id %q appears twice", p.ID)
		}
		seen[p.ID] = true
		if strings.TrimSpace(p.Methods) == "" {
			t.Errorf("%s has no method allowlist", p.ID)
		}
		if p.MaxBody <= 0 {
			t.Errorf("%s has no request-body ceiling", p.ID)
		}
		if p.LoginPaths != "" && p.LoginRPS <= 0 {
			t.Errorf("%s lists login paths without a rate", p.ID)
		}
		for _, part := range strings.Split(p.AdminIPs, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if _, err := netip.ParsePrefix(part); err != nil {
				if _, err := netip.ParseAddr(part); err != nil {
					t.Errorf("%s has a malformed admin range %q", p.ID, part)
				}
			}
		}
	}
	if _, ok := Get("generic"); !ok {
		t.Error("the generic preset is missing")
	}
	if _, ok := Get("nope"); ok {
		t.Error("Get accepted an unknown id")
	}
}

func TestProfileCarriesTheHostname(t *testing.T) {
	p, _ := Get("nextcloud")
	prof := p.Profile("cloud.example.com")
	if prof.Name != "Nextcloud (cloud.example.com)" {
		t.Fatalf("name = %q", prof.Name)
	}
	if prof.AllowedMethods != p.Methods || prof.MaxBody != p.MaxBody || prof.LoginRPS != p.LoginRPS {
		t.Fatal("the profile does not carry the preset's values")
	}
	if !strings.Contains(prof.AllowedMethods, "PROPFIND") {
		t.Fatal("the Nextcloud preset dropped the WebDAV verbs")
	}
	if prof.ID != 0 {
		t.Fatal("the built profile looks already stored")
	}
}
