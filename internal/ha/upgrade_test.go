package ha

import (
	"errors"
	"strings"
	"testing"
)

func nodeVersion(over NodeVersion) NodeVersion {
	out := NodeVersion{Node: "node-a", Role: "active", Version: "1.59.0", Schema: "25", Protocol: 1}
	if over.Node != "" {
		out.Node = over.Node
	}
	if over.Role != "" {
		out.Role = over.Role
	}
	if over.Version != "" {
		out.Version = over.Version
	}
	if over.Schema != "" {
		out.Schema = over.Schema
	}
	if over.Protocol != 0 {
		out.Protocol = over.Protocol
	}
	return out
}

func TestCheckUpgradeAcceptsAMatchingPair(t *testing.T) {
	peer := nodeVersion(NodeVersion{Node: "node-b", Role: "standby"})
	got := CheckUpgrade(nodeVersion(NodeVersion{}), &peer, nil)
	if !got.Compatible || !got.SameVersion || len(got.Problems) != 0 {
		t.Fatalf("matching pair = %+v", got)
	}
	if !strings.Contains(got.Advice, "standby first") {
		t.Fatalf("advice = %q", got.Advice)
	}
}

func TestCheckUpgradeRefusesASchemaMismatch(t *testing.T) {
	peer := nodeVersion(NodeVersion{Node: "node-b", Schema: "24"})
	got := CheckUpgrade(nodeVersion(NodeVersion{}), &peer, nil)
	if got.Compatible {
		t.Fatal("a schema mismatch was accepted")
	}
	if len(got.Problems) == 0 || !strings.Contains(got.Problems[0], "24") {
		t.Fatalf("problems = %v", got.Problems)
	}
	if !strings.Contains(got.Advice, "must agree") {
		t.Fatalf("advice = %q", got.Advice)
	}
}

func TestCheckUpgradeRefusesAProtocolMismatch(t *testing.T) {
	peer := nodeVersion(NodeVersion{Node: "node-b", Protocol: 2})
	got := CheckUpgrade(nodeVersion(NodeVersion{}), &peer, nil)
	if got.Compatible || len(got.Problems) == 0 {
		t.Fatalf("protocol mismatch = %+v", got)
	}
}

func TestCheckUpgradeAllowsAReleaseDifferenceMidUpgrade(t *testing.T) {
	peer := nodeVersion(NodeVersion{Node: "node-b", Version: "1.60.0"})
	got := CheckUpgrade(nodeVersion(NodeVersion{}), &peer, nil)
	if !got.Compatible || got.SameVersion {
		t.Fatalf("release difference = %+v", got)
	}
	if len(got.Problems) != 1 || !strings.Contains(got.Problems[0], "1.60.0") {
		t.Fatalf("problems = %v", got.Problems)
	}
}

func TestCheckUpgradeReportsAnUnreachablePeer(t *testing.T) {
	got := CheckUpgrade(nodeVersion(NodeVersion{}), nil, errors.New("dial tcp 10.0.0.11:9443: refused"))
	if got.Compatible {
		t.Fatal("an unreachable peer was accepted")
	}
	if len(got.Problems) != 1 || !strings.Contains(got.Problems[0], "refused") {
		t.Fatalf("problems = %v", got.Problems)
	}
}
