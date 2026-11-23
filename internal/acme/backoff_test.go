package acme

import (
	"testing"
	"time"
)

func TestRenewalBackoffDoublesAndCaps(t *testing.T) {
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 30 * time.Minute},
		{2, time.Hour},
		{3, 2 * time.Hour},
		{4, 4 * time.Hour},
		{5, 6 * time.Hour},
		{50, 6 * time.Hour},
	}
	for _, tc := range cases {
		if got := renewalBackoff(tc.attempt); got != tc.want {
			t.Fatalf("renewalBackoff(%d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}
}

func TestFailedRenewalBlocksTheNextAttempt(t *testing.T) {
	m := &Manager{retryAt: map[int64]time.Time{}, retryN: map[int64]int{}}
	now := time.Now()
	if !m.renewalAllowed(7, now) {
		t.Fatal("a certificate with no failure was blocked")
	}
	m.scheduleRetry(7, now)
	if m.renewalAllowed(7, now.Add(time.Minute)) {
		t.Fatal("a failed renewal was retried immediately")
	}
	if !m.renewalAllowed(7, now.Add(7*time.Hour)) {
		t.Fatal("the retry never became due")
	}
	m.clearRetry(7)
	if !m.renewalAllowed(7, now) {
		t.Fatal("clearing the retry did not unblock the certificate")
	}
}
