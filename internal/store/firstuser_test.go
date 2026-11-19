package store

import (
	"errors"
	"testing"
)

func TestCreateFirstUserOnlyOnce(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, err := st.CreateFirstUser("admin", "hash", "secret", "codes", true); err != nil {
		t.Fatalf("first setup failed: %v", err)
	}
	if _, err := st.CreateFirstUser("intruder", "hash", "secret", "codes", true); !errors.Is(err, ErrAlreadySetup) {
		t.Fatalf("second setup error = %v, want ErrAlreadySetup", err)
	}
	n, err := st.CountUsers()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("user count = %d, want 1", n)
	}
}
