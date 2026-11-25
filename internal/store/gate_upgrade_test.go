package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A database written before schema 28 has no gate_users.totp_last_step. The
// upgrade adds it without touching the account rows or signing anyone out.
func TestGateTOTPStepReachesAnExistingDatabase(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	const hash = "argon2id-hash"
	const secret = "sealed-totp-secret"
	id, err := st.CreateGateUser("operator", hash, secret, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO gate_sessions(id, proxy_id, username, created_at, expires_at)
		VALUES('session-1', 1, 'operator', '2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}

	// Rewind to what a schema-27 node wrote: the column and the version stamp.
	if _, err := st.db.Exec(`ALTER TABLE gate_users DROP COLUMN totp_last_step`); err != nil {
		t.Fatalf("rewind the column: %v", err)
	}
	if _, err := st.db.Exec(`UPDATE schema_meta SET value = '27' WHERE key = 'version'`); err != nil {
		t.Fatal(err)
	}
	if has, err := st.hasColumn("gate_users", "totp_last_step"); err != nil || has {
		t.Fatalf("the rewound database still has the column: %v, %v", has, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st, err = Open(dir)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer st.Close()

	has, err := st.hasColumn("gate_users", "totp_last_step")
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Fatal("the upgrade did not add gate_users.totp_last_step")
	}
	var version string
	if err := st.db.QueryRow(`SELECT value FROM schema_meta WHERE key = 'version'`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("schema version = %q, want %q", version, schemaVersion)
	}

	var gotHash, gotSecret string
	var enabled int
	var step int64
	if err := st.db.QueryRow(`SELECT password_hash, totp_secret, totp_enabled, totp_last_step
		FROM gate_users WHERE id = ?`, id).Scan(&gotHash, &gotSecret, &enabled, &step); err != nil {
		t.Fatalf("the gate account did not survive the upgrade: %v", err)
	}
	if gotHash != hash || gotSecret != secret || enabled != 1 {
		t.Fatalf("the upgraded account changed: hash=%q secret=%q enabled=%d", gotHash, gotSecret, enabled)
	}
	if step != 0 {
		t.Fatalf("totp_last_step = %d after the upgrade, want 0", step)
	}

	// A schema-27 node keeps its gate sessions: only a migration that changes
	// how a cookie is keyed signs anyone out.
	var sessions int
	if err := st.db.QueryRow(`SELECT count(*) FROM gate_sessions`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 {
		t.Fatalf("gate sessions = %d after the upgrade, want the existing one kept", sessions)
	}

	// The upgraded row can spend a code once, which is the whole point of the
	// column.
	const at = int64(3_000_000)
	ok, err := st.ClaimGateTOTPStep(id, at)
	if err != nil || !ok {
		t.Fatalf("first claim after upgrade = %v, %v; want true, nil", ok, err)
	}
	ok, err = st.ClaimGateTOTPStep(id, at)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("the upgraded account accepted the same step twice")
	}
}

// The same column must reach a database written by a real earlier release, not
// only one this code rewound itself.
func TestGateTOTPStepReachesThePreviousReleaseFixture(t *testing.T) {
	data, err := os.ReadFile(upgradeFixture)
	if err != nil {
		t.Fatalf("read fixture: %v (regenerate with WAFPROXY_WRITE_FIXTURE=1 go test -run TestWriteUpgradeFixture ./internal/store)", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wafproxy.db"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open the previous release's database: %v", err)
	}
	defer st.Close()
	has, err := st.hasColumn("gate_users", "totp_last_step")
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Fatal("the previous release's database did not gain gate_users.totp_last_step")
	}
}

// A snapshot from a node one migration behind must be refused before anything
// is cleared. OPERATIONS.md has the standby upgraded first exactly so the active
// never sends a schema the standby cannot read.
func TestRestoreRefusesSnapshotFromAnOlderSchema(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.CreateGateUser("keeper", "hash", "", false); err != nil {
		t.Fatal(err)
	}
	snap, err := st.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	// One migration behind: this release writes schemaVersion, and the node that
	// produced the dump still ran the previous one.
	const previous = "28"
	snap.SchemaVersion = previous
	// A dump that would empty the table, so a restore that reached the clear
	// step would leave no keeper behind.
	snap.Tables["gate_users"] = TableDump{Columns: []string{"id"}}

	err = st.Restore(snap)
	if err == nil {
		t.Fatalf("a snapshot from schema %s was accepted", previous)
	}
	if !strings.Contains(err.Error(), `"`+previous+`"`) || !strings.Contains(err.Error(), `"`+schemaVersion+`"`) {
		t.Fatalf("the refusal does not name both schemas: %v", err)
	}
	if _, err := st.GateUserByUsername("keeper"); err != nil {
		t.Fatalf("the refused snapshot still cleared data: %v", err)
	}
}
