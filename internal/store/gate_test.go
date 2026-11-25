package store

import (
	"testing"
	"time"
)

// A claimed authenticator step is spent: the same code, and any older one, is
// refused, while the next step still signs in.
func TestClaimGateTOTPStepIsMonotonic(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	id, err := st.CreateGateUser("visitor", "hash", "", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		step int64
		want bool
	}{
		{100, true},
		{100, false},
		{99, false},
		{101, true},
	} {
		got, err := st.ClaimGateTOTPStep(id, tc.step)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("step %d claimed = %v, want %v", tc.step, got, tc.want)
		}
	}
}

func TestGateFailureReportGroupsByAddressUsernameAndProxy(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	for i := 0; i < 3; i++ {
		if err := st.RecordGateFailure("203.0.113.9", 1, "admin", "bad-credentials"); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.RecordGateFailure("203.0.113.9", 1, "root", "blocked-username"); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordGateFailure("198.51.100.4", 2, "admin", "bad-credentials"); err != nil {
		t.Fatal(err)
	}

	rows, err := st.GateFailureReport(time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3 (one per address/username/proxy)", len(rows))
	}
	got := map[string]int{}
	for _, r := range rows {
		got[r.IP+"|"+r.Username+"|"+string(rune('0'+r.ProxyID))] = r.Attempts
		if r.First.IsZero() || r.Last.IsZero() {
			t.Errorf("row %+v has an empty timestamp", r)
		}
	}
	if got["203.0.113.9|admin|1"] != 3 {
		t.Errorf("admin attempts = %d, want 3", got["203.0.113.9|admin|1"])
	}
	if got["203.0.113.9|root|1"] != 1 {
		t.Errorf("root attempts = %d, want 1", got["203.0.113.9|root|1"])
	}

	// The range bounds are honoured; an outside window returns nothing.
	old, err := st.GateFailureReport(time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour), 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(old) != 0 {
		t.Errorf("got %d rows outside the window, want 0", len(old))
	}

	if err := st.ClearGateFailures("203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	rows, err = st.GateFailureReport(time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].IP != "198.51.100.4" {
		t.Fatalf("after clearing one address got %+v, want only the other", rows)
	}
}
