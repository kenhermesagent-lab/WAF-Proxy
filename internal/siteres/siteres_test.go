package siteres

import (
	"bytes"
	"io"
	"log/slog"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func newTestSet(t *testing.T) (*Set, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	box, err := wfcrypto.New(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	bans, err := ban.New(st, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	set, err := New(Deps{
		Store: st, Box: box, Log: log, Bans: bans,
		Geo: geoip.Open(t.TempDir()), Metrics: metrics.New("", ""),
	})
	if err != nil {
		t.Fatal(err)
	}
	return set, st
}

func TestNewBuildsOnlyTheDefaultSite(t *testing.T) {
	set, st := newTestSet(t)
	if got, want := set.DefaultID(), st.SiteID(); got != want {
		t.Fatalf("DefaultID() = %d, want the store's site %d", got, want)
	}
	def := set.Default()
	if def == nil || def.Site.ID != set.DefaultID() {
		t.Fatalf("Default() = %+v, want the default site's bundle", def)
	}
	if def.Store.SiteID() != set.DefaultID() {
		t.Fatal("the default bundle reads another site's rows")
	}
	seen := 0
	set.Each(func(*Bundle) { seen++ })
	if seen != 1 {
		t.Fatalf("Each visited %d bundles before any other site was built, want 1", seen)
	}
}

func TestForScopesEachSitesStore(t *testing.T) {
	set, st := newTestSet(t)
	site, err := st.CreateSite("bravo", "Bravo", "console.bravo.test")
	if err != nil {
		t.Fatal(err)
	}
	bravo, err := set.For(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bravo.Site.ID != site.ID || bravo.Store.SiteID() != site.ID {
		t.Fatalf("For(%d) built %+v reading site %d", site.ID, bravo.Site, bravo.Store.SiteID())
	}
	seen := 0
	set.Each(func(*Bundle) { seen++ })
	if seen != 2 {
		t.Fatalf("Each visited %d bundles, want 2", seen)
	}
	if err := set.Reload(site.ID); err != nil {
		t.Fatalf("Reload(%d) = %v", site.ID, err)
	}
}

// A site deleted before its bundle was built resolves to the default bundle,
// never to another tenant's.
func TestForFallsBackToTheDefaultAfterADelete(t *testing.T) {
	set, st := newTestSet(t)
	site, err := st.CreateSite("charlie", "Charlie", "console.charlie.test")
	if err != nil {
		t.Fatal(err)
	}
	// Not built first: a bundle already built stays until Drop.
	if err := st.DeleteSite(site.ID); err != nil {
		t.Fatal(err)
	}
	got, err := set.For(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Site.ID != set.DefaultID() {
		t.Fatalf("a deleted site resolved to site %d, want the default %d", got.Site.ID, set.DefaultID())
	}
}

func TestDropRebuildsTheSiteOnNextUse(t *testing.T) {
	set, st := newTestSet(t)
	site, err := st.CreateSite("delta", "Delta", "console.delta.test")
	if err != nil {
		t.Fatal(err)
	}
	first, err := set.For(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	set.Drop(site.ID)
	second, err := set.For(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("Drop kept the old bundle")
	}
	if second.Site.ID != site.ID {
		t.Fatalf("the rebuilt bundle is for site %d, want %d", second.Site.ID, site.ID)
	}
}
