package store

import (
	"testing"
	"time"
)

func TestSnapshotRestoreRoundTrip(t *testing.T) {
	src, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if err := src.Unscoped().SetSetting("ha.test", "alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := src.db.Exec(`INSERT INTO bans (cidr, reason, source, permanent, hits, created_by, created_at) VALUES ('203.0.113.0/24', 'test', 'manual', 0, 2, 'admin', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	snap, err := src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap.SchemaVersion != SchemaVersion() {
		t.Fatalf("snapshot schema %q", snap.SchemaVersion)
	}
	for _, local := range []string{"events", "flows", "schema_meta"} {
		if _, present := snap.Tables[local]; present {
			t.Fatalf("snapshot carried local table %s", local)
		}
	}
	if got := snap.Tables["bans"].Rows; len(got) != 1 {
		t.Fatalf("bans rows = %d, want 1", len(got))
	}

	dst, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if err := dst.Restore(snap); err != nil {
		t.Fatal(err)
	}
	v, err := dst.Unscoped().GetSetting("ha.test")
	if err != nil || v != "alpha" {
		t.Fatalf("restored setting = %q, %v", v, err)
	}
	if got, err := dst.Unscoped().BanByCIDR("203.0.113.0/24"); err != nil || got.Hits != 2 {
		t.Fatalf("restored ban = %+v, %v", got, err)
	}
	// Applying the same snapshot twice must not duplicate rows.
	if err := dst.Restore(snap); err != nil {
		t.Fatal(err)
	}
	if got, err := dst.Snapshot(); err != nil || len(got.Tables["bans"].Rows) != 1 {
		t.Fatalf("second restore left %d bans, %v", len(got.Tables["bans"].Rows), err)
	}
}

// The configuration digest is what keeps the standby's 30-second snapshot from
// rewriting live sessions on every tick.
func TestConfigHashTracksConfigurationOnly(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.SetSessionKey([]byte("0123456789abcdef0123456789abcdef"))
	userID, err := st.CreateUser("admin", "hash", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	base, err := st.ConfigHash()
	if err != nil {
		t.Fatal(err)
	}
	if len(base) != 64 {
		t.Fatalf("config hash = %q, want 64 hex characters", base)
	}

	// Streamed state must not move the configuration digest.
	if err := st.CreateSession("cookie", userID, "csrf", "", "", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, err := st.ConfigHash(); err != nil || got != base {
		t.Fatalf("a session changed the config hash: %s, %v", got, err)
	}

	if err := st.Unscoped().SetSetting("ha.probe", "one"); err != nil {
		t.Fatal(err)
	}
	changed, err := st.ConfigHash()
	if err != nil {
		t.Fatal(err)
	}
	if changed == base {
		t.Fatal("a settings change did not move the config hash")
	}
	// The digest is over content, not history: removing the row restores it.
	if _, err := st.db.Exec(`DELETE FROM settings WHERE key = 'ha.probe'`); err != nil {
		t.Fatal(err)
	}
	if got, err := st.ConfigHash(); err != nil || got != base {
		t.Fatalf("config hash is not canonical: %s, %v", got, err)
	}
}

// A session references its user with ON DELETE CASCADE. Clearing users after a
// session was restored used to wipe the session, so the restore has to clear
// every table before it inserts any row.
func TestRestoreKeepsRowsBehindACascade(t *testing.T) {
	src, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	src.SetSessionKey([]byte("0123456789abcdef0123456789abcdef"))
	userID, err := src.CreateUser("admin", "hash", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := src.CreateSession("cookie", userID, "csrf", "", "", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	snap, err := src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	dst, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	dst.SetSessionKey([]byte("0123456789abcdef0123456789abcdef"))
	if err := dst.Restore(snap); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.LookupSession("cookie"); err != nil {
		t.Fatalf("restore lost a session through the users cascade: %v", err)
	}
}

func TestRestoreRejectsWrongSchema(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	snap, err := st.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	snap.SchemaVersion = "1"
	if err := st.Restore(snap); err == nil {
		t.Fatal("Restore accepted a snapshot from another schema")
	}
}

func TestRestoreRejectsLocalTable(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	snap, err := st.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	snap.Tables["events"] = TableDump{Columns: []string{"id"}}
	if err := st.Restore(snap); err == nil {
		t.Fatal("Restore accepted a local table")
	}
}
