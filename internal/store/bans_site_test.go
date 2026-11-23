package store

import (
	"testing"
	"time"
)

// Bans are keyed by site and address, so reopening an install that banned the
// same address on two sites must not re-create the old global unique index.
func TestReopenKeepsSameAddressBannableOnTwoSites(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.CreateSite("two", "Two", "two.example.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range []int64{st.SiteID(), second.ID} {
		if _, err := st.db.Exec(`INSERT INTO bans(cidr, reason, source, permanent, hits, created_by, created_at, site_id)
			VALUES('203.0.113.9', 'test', 'manual', 1, 0, 'admin', ?, ?)`, stamp(time.Now()), site); err != nil {
			t.Fatalf("insert ban for site %d: %v", site, err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen after per-site bans: %v", err)
	}
	defer reopened.Close()
	var n int
	if err := reopened.Unscoped().db.QueryRow(`SELECT COUNT(*) FROM bans WHERE cidr = '203.0.113.9'`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("bans after reopen = %d (%v), want 2", n, err)
	}
}
