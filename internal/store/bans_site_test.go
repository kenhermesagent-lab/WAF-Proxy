package store

import (
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
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

// A binary rolled back to before sites keeps syncing bans that name no site.
// When one repeats an address the default site already bans, the next start
// must merge the pair instead of stopping at the (site_id, cidr) index.
func TestReopenMergesBanLeftUnownedByRolledBackBinary(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cidr := "198.51.100.7"
	soon := time.Now().Add(time.Hour)
	if _, err := st.AddBan(&model.Ban{CIDR: cidr, Reason: "manual ban", Source: "manual", ExpiresAt: &soon}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO bans(cidr, reason, source, permanent, hits, created_by, created_at, site_id)
		VALUES(?, 'crowdsec: ssh:bruteforce', 'crowdsec', 1, 0, 'crowdsec', ?, 0)`,
		cidr, stamp(time.Now().Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen after an unowned duplicate ban: %v", err)
	}
	defer reopened.Close()
	var n, permanent int
	var site int64
	if err := reopened.db.QueryRow(`SELECT COUNT(*), MAX(permanent), MAX(site_id) FROM bans WHERE cidr = ?`, cidr).
		Scan(&n, &permanent, &site); err != nil {
		t.Fatal(err)
	}
	if n != 1 || permanent != 1 || site != reopened.SiteID() {
		t.Fatalf("adopted ban = %d rows, permanent %d, site %d; want 1 permanent row on site %d",
			n, permanent, site, reopened.SiteID())
	}
}
