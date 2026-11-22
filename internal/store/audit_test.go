package store

import (
	"testing"
)

func TestAuditChainDetectsEdits(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	st.AddAudit("admin", "a", "one", "198.51.100.1")
	st.AddAudit("admin", "b", "two", "198.51.100.1")

	checked, broken, err := st.VerifyAuditChain()
	if err != nil {
		t.Fatal(err)
	}
	if checked != 2 || broken != 0 {
		t.Fatalf("verify = %d checked, broken %d; want an intact chain", checked, broken)
	}

	if _, err := st.db.Exec(`UPDATE audit SET detail = 'edited' WHERE action = 'b'`); err != nil {
		t.Fatal(err)
	}
	checked, broken, err = st.VerifyAuditChain()
	if err != nil {
		t.Fatal(err)
	}
	if broken == 0 {
		t.Fatalf("an edited row was not detected (checked %d)", checked)
	}
}
