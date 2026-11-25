package preset

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
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
		if len(p.Notes) == 0 {
			t.Errorf("%s has no guidance notes for the dialog", p.ID)
		}
		if p.ProxyMaxBody < 0 || p.ProxyMaxBody > model.MaxBodyCeiling {
			t.Errorf("%s suggests an out-of-range site ceiling %d", p.ID, p.ProxyMaxBody)
		}
		if len(p.BodySkipPaths) > 0 && len(p.Steps) == 0 {
			t.Errorf("%s skips body inspection without telling the operator the steps", p.ID)
		}
		for _, line := range p.BodySkipPaths {
			method, prefix, ok := strings.Cut(strings.TrimSpace(line), " ")
			if !ok || prefix == "" {
				t.Errorf("%s has a malformed skip path %q", p.ID, line)
				continue
			}
			switch method {
			case "POST", "PUT", "PATCH":
			default:
				t.Errorf("%s skips %s %q, but only POST, PUT and PATCH may be exempt", p.ID, method, prefix)
			}
			if !strings.HasPrefix(prefix, "/") || prefix == "/" {
				t.Errorf("%s skips the unsafe prefix %q", p.ID, prefix)
			}
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
	for _, id := range []string{
		"vaultwarden", "gitea", "paperless", "grafana", "uptime-kuma", "mealie", "navidrome",
		"photoprism", "syncthing", "n8n", "bookstack", "calcom", "arr",
		"immich", "firefly", "audiobookshelf", "openwebui", "containers", "frigate", "guacamole",
		"actual", "bookmarks", "rss", "wiki", "filesync", "filebrowser", "stirling", "matrix", "dnsadmin",
	} {
		if _, ok := Get(id); !ok {
			t.Errorf("preset %q is missing", id)
		}
	}
	if _, ok := Get("nope"); ok {
		t.Error("Get accepted an unknown id")
	}
}

// The console offers these gate modes; a preset that named anything else would
// preselect a value the drawer cannot send.
func TestGatesAreKnownModes(t *testing.T) {
	known := map[string]bool{"": true, "passphrase": true, "accounts": true, "accounts_totp": true, "forward_auth": true}
	for _, p := range All() {
		if !known[p.Gate] {
			t.Errorf("%s suggests unknown gate mode %q", p.ID, p.Gate)
		}
	}
}

// pathUnder mirrors how the policy engine matches an admin path, so a preset
// whose login path sits under its own admin prefix is caught here rather than
// by an operator locked out of the app from outside their network.
func pathUnder(p, prefix string) bool {
	p = strings.TrimSuffix(p, "/")
	prefix = strings.TrimSuffix(prefix, "/")
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

func TestAdminPathsNeverCoverALogin(t *testing.T) {
	for _, p := range All() {
		if strings.TrimSpace(p.AdminIPs) == "" {
			continue
		}
		for _, login := range strings.Split(p.LoginPaths, ",") {
			login = strings.TrimSpace(login)
			if login == "" {
				continue
			}
			for _, admin := range strings.Split(p.AdminPaths, ",") {
				admin = strings.TrimSpace(admin)
				if admin != "" && pathUnder(login, admin) {
					t.Errorf("%s: admin path %q covers login path %q, so a remote login is refused", p.ID, admin, login)
				}
			}
		}
	}
}

func TestBodyCeilingsStayInMemoryBudget(t *testing.T) {
	for _, p := range All() {
		if p.MaxBody > 128<<20 {
			t.Errorf("%s buffers %d MiB per request", p.ID, p.MaxBody>>20)
		}
	}
}

// The drawer draws the list in the order the API returns it, so the order is
// the library's, not each caller's.
func TestPresetsComeBackAlphabetical(t *testing.T) {
	list := All()
	if len(list) < 5 {
		t.Fatalf("got %d presets", len(list))
	}
	for i := 1; i < len(list); i++ {
		if sortKey(list[i-1].Name) > sortKey(list[i].Name) {
			t.Fatalf("%q comes before %q", list[i-1].Name, list[i].Name)
		}
	}
	// A leading symbol sorts under its letter instead of ahead of everything.
	for _, p := range list {
		if strings.HasPrefix(p.Name, "*") && sortKey(p.Name) == p.Name {
			t.Errorf("%s keeps its symbol in the sort key", p.ID)
		}
	}
}

// Every preset ships response hardening that fits the app: the conservative
// baseline, and the browser features the app actually uses allowed back for its
// own origin.
func TestProtectionProfilesFitTheApp(t *testing.T) {
	browserApps := map[string]string{"nextcloud": "microphone=(self)", "openwebui": "microphone=(self)"}
	for _, p := range All() {
		prof := p.ProtectionProfile("app.example.com")
		if prof.ID != 0 || prof.Builtin {
			t.Errorf("%s built a profile that looks already stored: %+v", p.ID, prof)
		}
		if want := p.Name + " hardening (app.example.com)"; prof.Name != want {
			t.Errorf("%s protection profile name = %q, want %q", p.ID, prof.Name, want)
		}
		if !prof.ForceHTTPS || !prof.HSTS || !prof.HSTSSubdomains || !prof.NoSniff || !prof.HideServer {
			t.Errorf("%s ships a profile without the baseline hardening: %+v", p.ID, prof)
		}
		switch prof.FrameOptions {
		case "sameorigin", "deny", "off":
		default:
			t.Errorf("%s frame options = %q", p.ID, prof.FrameOptions)
		}
		if prof.ReferrerPolicy == "" {
			t.Errorf("%s has no referrer policy", p.ID)
		}
		wantFeature, records := browserApps[p.ID]
		if !records && strings.Contains(prof.PermissionsPolicy, "=(self)") {
			t.Errorf("%s allows a browser feature without recording why", p.ID)
		}
		if records && !strings.Contains(prof.PermissionsPolicy, wantFeature) {
			t.Errorf("%s must allow %s, got %q", p.ID, wantFeature, prof.PermissionsPolicy)
		}
	}
	// The list above is only useful while every app it names exists.
	for id := range browserApps {
		if _, ok := Get(id); !ok {
			t.Errorf("preset %q is missing", id)
		}
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
