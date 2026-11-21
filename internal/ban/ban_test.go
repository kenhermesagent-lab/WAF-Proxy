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
