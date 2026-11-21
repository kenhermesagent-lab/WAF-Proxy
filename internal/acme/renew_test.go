package acme

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func TestRenewalTimePolicies(t *testing.T) {
	issued := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	expires := issued.Add(90 * 24 * time.Hour)
	cases := []struct {
		mode string
		want time.Time
	}{
		{model.CertRenewMonthly, issued.AddDate(0, 1, 0)},
		{model.CertRenewEvery2Months, issued.AddDate(0, 2, 0)},
		// A 90-day certificate cannot wait a full quarter; renew before it lapses.
		{model.CertRenewEvery3Months, expires.Add(-renewSafetyWindow)},
		{model.CertRenewBeforeExpiry, expires.AddDate(0, -1, 0)},
	}
	for _, tc := range cases {
		c := model.Cert{IssuedAt: &issued, ExpiresAt: &expires, RenewMode: tc.mode}
		at, ok := renewalTime(c)
		if !ok || !at.Equal(tc.want) {
			t.Errorf("%s renewal time = (%v, %v), want %v", tc.mode, at, ok, tc.want)
		}
	}
}

func TestRenewalDueAtPolicyBoundary(t *testing.T) {
	issued := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	expires := issued.Add(90 * 24 * time.Hour)
	cases := []struct {
		name string
		mode string
		at   time.Time
	}{
		{"monthly", model.CertRenewMonthly, issued.AddDate(0, 1, 0)},
		{"two months", model.CertRenewEvery2Months, issued.AddDate(0, 2, 0)},
		{"three months safety cap", model.CertRenewEvery3Months, expires.Add(-renewSafetyWindow)},
		{"before expiry", model.CertRenewBeforeExpiry, expires.AddDate(0, -1, 0)},
	}
	for _, tc := range cases {
		c := model.Cert{IssuedAt: &issued, ExpiresAt: &expires, RenewMode: tc.mode}
		if renewalDue(c, tc.at.Add(-time.Second)) {
			t.Errorf("%s renewed before %v", tc.name, tc.at)
		}
		if !renewalDue(c, tc.at) {
			t.Errorf("%s did not renew at %v", tc.name, tc.at)
		}
	}
}

func TestFailedRenewalKeepsPreviousCertificate(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, err := st.SaveCert(&model.Cert{
		Domains: "example.com", Provider: "duckdns", Status: "renewing", CertPEM: []byte("old"),
	})
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{st: st, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	m.fail(id, errors.New("ACME unavailable"))

	cert, err := st.GetCert(id)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Status != "issued" {
		t.Fatalf("status = %q, want issued", cert.Status)
	}
	if cert.LastError == "" {
		t.Fatal("renewal error was not recorded")
	}
}

func TestRenewalFallsBackWithoutIssuedAt(t *testing.T) {
	expires := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	c := model.Cert{ExpiresAt: &expires, RenewMode: model.CertRenewMonthly}
	at, ok := renewalTime(c)
	want := expires.AddDate(0, -1, 0)
	if !ok || !at.Equal(want) {
		t.Fatalf("renewal time = (%v, %v), want %v", at, ok, want)
	}
}
