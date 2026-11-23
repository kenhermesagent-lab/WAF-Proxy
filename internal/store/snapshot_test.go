package store

import (
	"testing"
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
