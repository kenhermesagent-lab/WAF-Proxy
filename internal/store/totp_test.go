package store

import "testing"

func TestClaimTOTPStepRejectsReplay(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	id, err := st.CreateFirstUser("admin", "hash", "secret", "codes", true)
	if err != nil {
		t.Fatal(err)
	}
	step := int64(1_000_000)

	ok, err := st.ClaimTOTPStep(id, step)
	if err != nil || !ok {
		t.Fatalf("first claim = %v, %v; want true, nil", ok, err)
	}
	ok, err = st.ClaimTOTPStep(id, step)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("the same step was accepted twice")
	}
	// The next step is still usable.
	ok, err = st.ClaimTOTPStep(id, step+1)
	if err != nil || !ok {
		t.Fatalf("next step claim = %v, %v; want true, nil", ok, err)
	}
}

func TestMigrateAddsTOTPStepColumn(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	has, err := st.hasColumn("users", "totp_last_step")
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Fatal("users.totp_last_step was not migrated")
	}
	var version string
	if err := st.db.QueryRow(`SELECT value FROM schema_meta WHERE key = 'version'`).Scan(&version); err != nil {
		t.Fatalf("schema version not recorded: %v", err)
	}
	if version != schemaVersion {
		t.Fatalf("schema version = %q, want %q", version, schemaVersion)
	}
}
