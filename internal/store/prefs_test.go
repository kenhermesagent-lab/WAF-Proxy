package store

import "testing"

func TestPrefsAreScopedToTheUser(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.SetPref(1, "readiness.done", "1"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := st.SetPref(2, "readiness.done", "0"); err != nil {
		t.Fatalf("set other: %v", err)
	}
	prefs, err := st.Prefs(1)
	if err != nil {
		t.Fatalf("prefs: %v", err)
	}
	if prefs["readiness.done"] != "1" {
		t.Fatalf("user 1 reads %q, want 1", prefs["readiness.done"])
	}

	if err := st.SetPref(1, "readiness.done", ""); err != nil {
		t.Fatalf("clear: %v", err)
	}
	prefs, err = st.Prefs(1)
	if err != nil {
		t.Fatalf("prefs: %v", err)
	}
	if _, ok := prefs["readiness.done"]; ok {
		t.Fatal("an empty value should remove the preference")
	}
}
