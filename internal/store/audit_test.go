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

	checked, problem, err := st.VerifyAuditChain()
	if err != nil {
		t.Fatal(err)
	}
	if checked != 2 || problem != "" {
		t.Fatalf("verify = %d checked, %q; want an intact chain", checked, problem)
	}

	if _, err := st.db.Exec(`UPDATE audit SET detail = 'edited' WHERE action = 'b'`); err != nil {
		t.Fatal(err)
	}
	checked, problem, err = st.VerifyAuditChain()
	if err != nil {
		t.Fatal(err)
	}
	if problem == "" {
		t.Fatalf("an edited row was not detected (checked %d)", checked)
	}
}

func TestAuditChainDetectsDeletedTail(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	st.AddAudit("admin", "a", "one", "198.51.100.1")
	st.AddAudit("admin", "b", "two", "198.51.100.1")
	if _, err := st.db.Exec(`DELETE FROM audit WHERE action = 'b'`); err != nil {
		t.Fatal(err)
	}
	checked, problem, err := st.VerifyAuditChain()
	if err != nil {
		t.Fatal(err)
	}
	if checked != 1 || problem == "" {
		t.Fatalf("verify = %d checked, %q; want the removed tail reported", checked, problem)
	}
}
