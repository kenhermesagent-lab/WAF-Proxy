package store

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func openTempStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestDefaultSiteIsCreated(t *testing.T) {
	st := openTempStore(t)
	site, err := st.SiteBySlug(DefaultSiteSlug)
	if err != nil {
		t.Fatalf("default site: %v", err)
	}
	if !site.Enabled || site.Name != "Default" {
		t.Fatalf("default site = %+v", site)
	}
	if n, err := st.CountUsers(); err != nil || n != 0 {
		t.Fatalf("users = %d (%v)", n, err)
	}
}

func TestCreateSiteRejectsBadInputAndDuplicates(t *testing.T) {
	st := openTempStore(t)
	if _, err := st.CreateSite("Bad Slug", "x", ""); err == nil {
		t.Fatal("a slug with a space was accepted")
	}
	if _, err := st.CreateSite("a", "x", ""); err == nil {
		t.Fatal("a one-character slug was accepted")
	}
	if _, err := st.CreateSite("acme", "Acme", "console.acme.example"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := st.CreateSite("acme", "Again", ""); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate slug err = %v, want ErrDuplicate", err)
	}
	if _, err := st.CreateSite("beta", "Beta", "console.acme.example"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate console host err = %v, want ErrDuplicate", err)
	}
	// The same host with a port, different case and a trailing dot is the same
	// host; a second site must not claim it.
	if _, err := st.CreateSite("gamma", "Gamma", "Console.ACME.example.:8443"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("normalised duplicate err = %v, want ErrDuplicate", err)
	}
}

func TestSiteByConsoleHostNormalizes(t *testing.T) {
	st := openTempStore(t)
	if _, err := st.CreateSite("acme", "Acme", "console.acme.example"); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"console.acme.example", "CONSOLE.acme.example.", "console.acme.example:8443"} {
		site, err := st.SiteByConsoleHost(host)
		if err != nil {
			t.Fatalf("%q: %v", host, err)
		}
		if site.Slug != "acme" {
			t.Fatalf("%q resolved to %q", host, site.Slug)
		}
	}
	if _, err := st.SiteByConsoleHost("console.other.example"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown host err = %v, want ErrNotFound", err)
	}
}

func TestDefaultSiteAdoptsRowsFromThePreviousRelease(t *testing.T) {
	data, err := os.ReadFile(upgradeFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wafproxy.db"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer st.Close()

	site, err := st.SiteBySlug(DefaultSiteSlug)
	if err != nil {
		t.Fatalf("default site: %v", err)
	}
	// The domain the install already advertised becomes its console host.
	if site.ConsoleHost != "upgrade.example.com" {
		t.Fatalf("console host = %q", site.ConsoleHost)
	}
	for _, table := range []string{"users", "proxies", "policies", "access_lists", "certificates"} {
		var unowned int
		if err := st.db.QueryRow(`SELECT COUNT(*) FROM ` + table + ` WHERE site_id = 0`).Scan(&unowned); err != nil {
			t.Fatal(err)
		}
		if unowned != 0 {
			t.Fatalf("%s has %d rows without a site", table, unowned)
		}
	}
	proxies, err := st.ListProxies()
	if err != nil || len(proxies) != 1 {
		t.Fatalf("proxies = %d (%v)", len(proxies), err)
	}
}

func TestSettingsForOverlaysSiteOverHost(t *testing.T) {
	st := openTempStore(t)
	site, err := st.CreateSite("acme", "Acme", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("retention_days", "30"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSettingsFor(site.ID, map[string]string{
		"retention_days": "7",
		"base_domain":    "acme.example",
		"wan_ip":         "203.0.113.9",
	}); err != nil {
		t.Fatal(err)
	}
	kv, err := st.SettingsFor(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if kv["retention_days"] != "7" || kv["base_domain"] != "acme.example" {
		t.Fatalf("site settings = %v", kv)
	}
	if kv["wan_ip"] == "203.0.113.9" {
		t.Fatal("a site overrode a host-wide key")
	}
	host, err := st.SettingsFor(1)
	if err != nil {
		t.Fatal(err)
	}
	if host["retention_days"] != "30" {
		t.Fatalf("default site inherited %q", host["retention_days"])
	}
}

func TestDeleteSiteRemovesOnlyItsRows(t *testing.T) {
	st := openTempStore(t)
	defaultSite, err := st.SiteBySlug(DefaultSiteSlug)
	if err != nil {
		t.Fatal(err)
	}
	site, err := st.CreateSite("acme", "Acme", "console.acme.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		site int64
		host string
	}{{site.ID, "app.acme.example"}, {defaultSite.ID, "app.default.example"}} {
		if _, err := st.db.Exec(`INSERT INTO proxies(hostname, created_at, site_id) VALUES(?, '2026-01-01T00:00:00Z', ?)`,
			row.host, row.site); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.DeleteSite(defaultSite.ID); err == nil {
		t.Fatal("the default site was deleted")
	}
	if err := st.DeleteSite(site.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	var acme, kept int
	_ = st.db.QueryRow(`SELECT COUNT(*) FROM proxies WHERE hostname = 'app.acme.example'`).Scan(&acme)
	_ = st.db.QueryRow(`SELECT COUNT(*) FROM proxies WHERE hostname = 'app.default.example'`).Scan(&kept)
	if acme != 0 || kept != 1 {
		t.Fatalf("after delete: acme=%d default=%d", acme, kept)
	}
	if _, err := st.SiteBySlug("acme"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted site still resolves: %v", err)
	}
}

// A rolled-back binary keeps saving views that name no site. When one repeats
// a name the default site already saved, the next start must keep the newer
// definition instead of stopping at the (site_id, name) key.
func TestReopenMergesLogViewLeftUnownedByRolledBackBinary(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveLogView("errors", "status = 500", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO log_views(name, query, updated_by, updated_at, site_id)
		VALUES('errors', 'status >= 400', 'ops', ?, 0)`, stamp(time.Now().Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen after an unowned duplicate view: %v", err)
	}
	defer reopened.Close()
	views, err := reopened.ListLogViews()
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].Name != "errors" || views[0].Query != "status >= 400" || views[0].UpdatedBy != "ops" {
		t.Fatalf("adopted views = %+v, want only the newer errors view", views)
	}
	var site int64
	if err := reopened.db.QueryRow(`SELECT site_id FROM log_views WHERE name = 'errors'`).Scan(&site); err != nil || site != reopened.SiteID() {
		t.Fatalf("view site = %d (%v), want %d", site, err, reopened.SiteID())
	}
}

// TestAdoptionMergesEverySiteUniqueKey keeps a new per-site key from bringing
// back the adoption loop: every unique key that includes site_id on an adopted
// table must have an entry in adoptMerges.
func TestAdoptionMergesEverySiteUniqueKey(t *testing.T) {
	st := openTempStore(t)
	adopted := map[string]bool{}
	for _, table := range scopedTables {
		adopted[table] = true
	}
	for _, table := range queryStrings(t, st, `SELECT name FROM sqlite_master
		WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`) {
		if !adopted[table] {
			continue
		}
		for _, index := range queryStrings(t, st, `SELECT name FROM pragma_index_list(?) WHERE "unique" = 1`, table) {
			cols := queryStrings(t, st, `SELECT name FROM pragma_index_info(?) ORDER BY seqno`, index)
			if !slices.Contains(cols, "site_id") {
				continue
			}
			if _, ok := adoptMerges[table]; !ok {
				t.Errorf("%s has a unique key on %v that includes site_id, but adoptMerges has no entry for it", table, cols)
			}
		}
	}
}

func queryStrings(t *testing.T, st *Store, query string, args ...any) []string {
	t.Helper()
	rows, err := st.db.Query(query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
