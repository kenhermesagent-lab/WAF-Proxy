package ban

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func newTestEngine(t *testing.T) (*Engine, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	engine, err := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	return engine, st
}

func banHits(t *testing.T, st *store.Store, cidr string) int64 {
	t.Helper()
	b, err := st.BanByCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return b.Hits
}

func TestNoteHitBatchesUntilFlush(t *testing.T) {
	engine, st := newTestEngine(t)
	rec, err := engine.Add("198.51.100.7", "test", "manual", "tester", 0)
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("198.51.100.7")
	for i := 0; i < 5; i++ {
		engine.NoteHit(addr)
	}
	if n := banHits(t, st, rec.CIDR); n != 0 {
		t.Fatalf("hit counter written on the request path: %d", n)
	}
	engine.flushHits()
	if n := banHits(t, st, rec.CIDR); n != 5 {
		t.Fatalf("batched hits = %d, want 5", n)
	}
	// A flush with nothing pending must not write again.
	engine.flushHits()
	if n := banHits(t, st, rec.CIDR); n != 5 {
		t.Fatalf("second flush changed the counter: %d", n)
	}
}

func TestPromoteResolvesBansOutsideTheListCap(t *testing.T) {
	engine, st := newTestEngine(t)
	// The dashboard list is capped at 2000 rows, so this ban is invisible to it.
	old := &model.Ban{CIDR: "10.1.2.3/32", Reason: "old", Source: "manual", CreatedAt: time.Now().Add(-time.Hour)}
	oldID, err := st.AddBan(old)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2001; i++ {
		cidr := fmt.Sprintf("198.51.%d.%d", i/256, i%256)
		if _, err := st.AddBan(&model.Ban{CIDR: cidr, Reason: "filler", Source: "feed"}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := st.ListBans(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2000 {
		t.Fatalf("list cap changed: got %d rows", len(list))
	}
	for _, b := range list {
		if b.ID == oldID {
			t.Fatal("test setup no longer puts the oldest ban outside the cap")
		}
	}
	if err := engine.Promote(old.CIDR); err != nil {
		t.Fatal(err)
	}
	got, err := st.BanByID(oldID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Permanent || got.ExpiresAt != nil {
		t.Fatalf("ban not promoted: %+v", got)
	}
	if _, ok := engine.Match(netip.MustParseAddr("10.1.2.3")); !ok {
		t.Fatal("promoted ban is not enforced in memory")
	}
}

func TestPromoteUnknownBan(t *testing.T) {
	engine, _ := newTestEngine(t)
	if err := engine.Promote("203.0.113.9"); err != store.ErrNotFound {
		t.Fatalf("promote unknown ban = %v, want ErrNotFound", err)
	}
}

func TestAddForRecordsTheBanOnTheObservingSite(t *testing.T) {
	engine, st := newTestEngine(t)
	site, err := st.CreateSite("bravo", "Bravo", "console.bravo.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.AddFor(site.ID, "198.51.100.0/24", "request rate exceeded", "ratelimit", "policy", time.Minute); err != nil {
		t.Fatal(err)
	}

	bravo := st.InSite(site.ID)
	bans, err := bravo.ListBans(true)
	if err != nil || len(bans) != 1 || bans[0].CIDR != "198.51.100.0/24" {
		t.Fatalf("bravo bans = %+v (%v)", bans, err)
	}
	if def, err := st.ListBans(true); err != nil || len(def) != 0 {
		t.Fatalf("the default site lists another site's ban: %+v (%v)", def, err)
	}
	// Records are per site; the address is still dropped for every site.
	if _, banned := engine.Match(netip.MustParseAddr("198.51.100.5")); !banned {
		t.Fatal("the kernel set does not hold the ban")
	}
}

// A ban the one-shot CLI deleted must stop dropping traffic without a restart,
// or an operator who lifts a ban sees it still enforced.
func TestReconcileDropsABanDeletedBehindTheEngine(t *testing.T) {
	engine, st := newTestEngine(t)
	rec, err := engine.Add("198.51.100.7", "test", "manual", "tester", 0)
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("198.51.100.7")
	if _, err := st.DeleteBanByCIDR(rec.CIDR); err != nil {
		t.Fatal(err)
	}
	if _, ok := engine.Match(addr); !ok {
		t.Fatal("the ban was dropped before Reconcile, so the test proves nothing")
	}
	engine.Reconcile()
	if _, ok := engine.Match(addr); ok {
		t.Fatal("Reconcile kept a ban the database no longer has")
	}
}

// Removing a CrowdSec decision must not lift a manual or WAF ban.
func TestRemoveIfSourceLeavesAnotherSourcesBan(t *testing.T) {
	engine, _ := newTestEngine(t)
	rec, err := engine.Add("198.51.100.8", "crowdsec decision", "crowdsec", "crowdsec", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("198.51.100.8")
	engine.RemoveIfSource(rec.CIDR, "manual")
	if _, ok := engine.Match(addr); !ok {
		t.Fatal("a crowdsec removal lifted a ban another source created")
	}
	engine.RemoveIfSource(rec.CIDR, "crowdsec")
	if _, ok := engine.Match(addr); ok {
		t.Fatal("the owning source's removal left the ban in place")
	}
}

// A temporary refresh must not shorten a permanent ban.
func TestAddKeepsAPermanentBan(t *testing.T) {
	engine, st := newTestEngine(t)
	rec, err := engine.Add("198.51.100.9", "manual", "manual", "tester", 0)
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := engine.Add(rec.CIDR, "rate limit", "ratelimit", "policy", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !refreshed.Permanent || refreshed.ExpiresAt != nil {
		t.Fatalf("a permanent ban was downgraded to %+v", refreshed)
	}
	row, err := st.BanByCIDR(rec.CIDR)
	if err != nil {
		t.Fatal(err)
	}
	if !row.Permanent || row.ExpiresAt != nil {
		t.Fatalf("the stored ban was downgraded to %+v", row)
	}
}

func TestDemoteShortensAPermanentBan(t *testing.T) {
	engine, st := newTestEngine(t)
	rec, err := engine.Add("198.51.100.10", "manual", "manual", "tester", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Demote(rec.CIDR, time.Minute); err != nil {
		t.Fatal(err)
	}
	row, err := st.BanByCIDR(rec.CIDR)
	if err != nil {
		t.Fatal(err)
	}
	if row.Permanent || row.ExpiresAt == nil {
		t.Fatalf("demoted ban is still permanent: %+v", row)
	}
	if got, ok := engine.Match(netip.MustParseAddr("198.51.100.10")); !ok || got.Permanent {
		t.Fatalf("in-memory record after demote = %+v (%v)", got, ok)
	}
}

// The sweeper must drop both the enforcing entry and the row, or an expired
// cool-down keeps dropping traffic and stays in the console forever.
func TestPurgeExpiredRemovesRowsAndMemory(t *testing.T) {
	engine, st := newTestEngine(t)
	rec, err := engine.Add("198.51.100.11", "cool-down", "ratelimit", "policy", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	engine.purgeExpired()
	if n := engine.Count(); n != 0 {
		t.Fatalf("expired bans still enforced: %d", n)
	}
	if _, err := st.BanByCIDR(rec.CIDR); err == nil {
		t.Fatal("the expired row is still in the database")
	}
}
