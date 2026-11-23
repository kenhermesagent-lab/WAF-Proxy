package ha

import (
	"context"
	"strings"
	"testing"
	"time"
)

func goodPreflight() PreflightInput {
	return PreflightInput{
		PeerReachable:       true,
		LocalCluster:        "cluster-1",
		PeerCluster:         "cluster-1",
		LocalSchema:         "25",
		PeerSchema:          "25",
		LocalProtocol:       ProtocolVersion,
		PeerProtocol:        ProtocolVersion,
		LocalEpoch:          3,
		PeerEpoch:           3,
		LocalConfigHash:     strings.Repeat("a", 64),
		PeerConfigHash:      strings.Repeat("a", 64),
		Lag:                 time.Second,
		DatabaseWritable:    true,
		QuickCheck:          "ok",
		DiskFreePercent:     50,
		ClockSkew:           500 * time.Millisecond,
		ConfigWriteInFlight: false,
	}
}

func TestPreflightPassesCleanInput(t *testing.T) {
	checks := EvaluatePreflight(goodPreflight())
	if len(checks) != 12 {
		t.Fatalf("preflight returned %d checks, want 12", len(checks))
	}
	for _, c := range checks {
		if !c.OK {
			t.Fatalf("check %s failed on a clean input: %s", c.Name, c.Detail)
		}
	}
	if fail := FirstFailure(checks); fail != nil {
		t.Fatalf("FirstFailure = %+v on a clean input", fail)
	}
}

func TestPreflightFailsOneCheckAtATime(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*PreflightInput)
	}{
		{"peer-reachable", func(in *PreflightInput) { in.PeerReachable = false }},
		{"cluster", func(in *PreflightInput) { in.PeerCluster = "cluster-2" }},
		{"cluster", func(in *PreflightInput) { in.LocalCluster = "" }},
		{"schema", func(in *PreflightInput) { in.PeerSchema = "24" }},
		{"protocol", func(in *PreflightInput) { in.PeerProtocol = ProtocolVersion + 1 }},
		{"epoch", func(in *PreflightInput) { in.PeerEpoch = 4 }},
		{"config-hash", func(in *PreflightInput) { in.PeerConfigHash = strings.Repeat("b", 64) }},
		{"replication-lag", func(in *PreflightInput) { in.Lag = MaxReplicationLag + time.Millisecond }},
		{"certificates", func(in *PreflightInput) { in.MissingCertificates = []string{"shop.example"} }},
		{"database", func(in *PreflightInput) { in.DatabaseWritable = false }},
		{"database", func(in *PreflightInput) { in.QuickCheck = "*** in database main ***" }},
		{"disk", func(in *PreflightInput) { in.DiskFreePercent = MinDiskFreePercent - 0.1 }},
		{"clock-skew", func(in *PreflightInput) { in.ClockSkew = -MaxClockSkew - time.Second }},
		{"config-write", func(in *PreflightInput) { in.ConfigWriteInFlight = true }},
	}
	for _, tc := range cases {
		in := goodPreflight()
		tc.mutate(&in)
		checks := EvaluatePreflight(in)
		fail := FirstFailure(checks)
		if fail == nil {
			t.Fatalf("%s: no check failed", tc.name)
		}
		if fail.Name != tc.name {
			t.Fatalf("expected %s to fail first, got %s (%s)", tc.name, fail.Name, fail.Detail)
		}
		if fail.Fix == "" {
			t.Fatalf("%s failed without a fix", tc.name)
		}
	}
}

func TestGatherPreflightReadsThePeer(t *testing.T) {
	_, dirB, _, stB, _, _ := pairForTest(t)
	if _, err := SyncSnapshotOnce(context.Background(), dirB, stB); err != nil {
		t.Fatal(err)
	}
	in, err := GatherPreflight(context.Background(), PreflightSource{DataDir: dirB, Store: stB})
	if err != nil {
		t.Fatal(err)
	}
	if !in.PeerReachable || in.PeerCluster == "" || in.LocalCluster != in.PeerCluster {
		t.Fatalf("peer facts = %+v", in)
	}
	if in.PeerSchema != in.LocalSchema || in.PeerProtocol != ProtocolVersion || in.PeerEpoch != in.LocalEpoch {
		t.Fatalf("peer agreement = %+v", in)
	}
	if in.LocalConfigHash == "" || in.LocalConfigHash != in.PeerConfigHash {
		t.Fatalf("config hashes: local %q peer %q", in.LocalConfigHash, in.PeerConfigHash)
	}
	if !in.DatabaseWritable || in.QuickCheck != "ok" {
		t.Fatalf("database check = %+v", in)
	}
	if in.DiskFreePercent <= 0 {
		t.Fatalf("disk free = %.1f%%", in.DiskFreePercent)
	}
	checks := EvaluatePreflight(in)
	for _, c := range checks {
		if !c.OK && c.Name != "certificates" {
			t.Fatalf("gathered preflight failed %s: %s", c.Name, c.Detail)
		}
	}
}
