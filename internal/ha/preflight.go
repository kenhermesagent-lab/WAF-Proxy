package ha

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// ProtocolVersion changes whenever a link endpoint or payload changes shape. A
// pair must agree on it before either side moves traffic.
const ProtocolVersion = 1

const (
	// MaxReplicationLag is the worst staleness a planned move accepts.
	MaxReplicationLag = 5 * time.Second
	// MaxClockSkew is how far the two nodes' clocks may disagree.
	MaxClockSkew = 5 * time.Second
	// MinDiskFreePercent keeps certificate renewals and WAL growth possible.
	MinDiskFreePercent = 5.0
)

// Check is one preflight result. Fix is what the operator should do next, so a
// refusal is actionable rather than a bare boolean.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// PreflightInput is everything the checks need. Filling it is separate from
// judging it, so a test can fail one check at a time without a second node.
type PreflightInput struct {
	PeerReachable       bool
	LocalCluster        string
	PeerCluster         string
	LocalSchema         string
	PeerSchema          string
	LocalProtocol       int
	PeerProtocol        int
	LocalEpoch          int64
	PeerEpoch           int64
	LocalConfigHash     string
	PeerConfigHash      string
	Lag                 time.Duration
	MissingCertificates []string
	DatabaseWritable    bool
	QuickCheck          string
	DiskFreePercent     float64
	ClockSkew           time.Duration
	ConfigWriteInFlight bool
}

// PreflightSource is what a live node can read without asking the peer twice.
type PreflightSource struct {
	DataDir             string
	Store               *store.Store
	MissingCertificates func() []string
	ConfigWriteInFlight func() bool
	Now                 func() time.Time
}

// GatherPreflight reads the local node, then the peer's cheap config version,
// and returns the input the checks run on. A peer that cannot be reached is an
// input, not an error: the reachability check reports it.
func GatherPreflight(ctx context.Context, src PreflightSource) (PreflightInput, error) {
	now := time.Now
	if src.Now != nil {
		now = src.Now
	}
	in := PreflightInput{
		LocalSchema:      store.SchemaVersion(),
		LocalProtocol:    ProtocolVersion,
		DiskFreePercent:  100,
		DatabaseWritable: false,
	}
	node, err := Load(src.DataDir)
	if err != nil {
		return in, err
	}
	in.LocalEpoch = node.Epoch
	var ackSeq int64
	var ackAt time.Time
	if pair, err := LoadPair(src.DataDir); err == nil && pair != nil {
		in.LocalCluster = pair.ClusterID
		if seq, at, err := src.Store.PeerAck(pair.PeerFingerprint); err == nil {
			ackSeq, ackAt = seq, at
		}
	}
	if hash, err := src.Store.ConfigHash(); err == nil {
		in.LocalConfigHash = hash
	}
	if writable, err := src.Store.Writable(); err == nil {
		in.DatabaseWritable = writable
	}
	if qc, err := src.Store.QuickCheck(); err == nil {
		in.QuickCheck = qc
	}
	if pct, err := diskFreePercent(src.DataDir); err == nil {
		in.DiskFreePercent = pct
	}
	if src.MissingCertificates != nil {
		in.MissingCertificates = src.MissingCertificates()
	}
	if src.ConfigWriteInFlight != nil {
		in.ConfigWriteInFlight = src.ConfigWriteInFlight()
	}
	if in.LocalCluster != "" {
		if ver, err := ConfigVersion(ctx, src.DataDir); err == nil {
			in.PeerReachable = true
			in.PeerCluster = ver.ClusterID
			in.PeerEpoch = ver.Epoch
			in.PeerSchema = ver.Schema
			in.PeerProtocol = ver.Protocol
			in.PeerConfigHash = ver.Hash
			if t, err := time.Parse(time.RFC3339Nano, ver.Time); err == nil {
				in.ClockSkew = now().Sub(t)
			}
			// Lag is outstanding work, not the age of the last ack: an idle
			// pair that acknowledged hours ago is not behind.
			if ackSeq < ver.OutboxSeq && !ackAt.IsZero() {
				in.Lag = now().Sub(ackAt)
			}
		}
	}
	return in, nil
}

// EvaluatePreflight runs every check in the order an operator should fix them.
func EvaluatePreflight(in PreflightInput) []Check {
	return []Check{
		checkPeer(in),
		checkCluster(in),
		checkSchema(in),
		checkProtocol(in),
		checkEpoch(in),
		checkHash(in),
		checkLag(in),
		checkCertificates(in),
		checkDatabase(in),
		checkDisk(in),
		checkSkew(in),
		checkConfigWrite(in),
	}
}

// FirstFailure names the first check that failed, which is the one the operator
// should fix before the next attempt.
func FirstFailure(checks []Check) *Check {
	for i := range checks {
		if !checks[i].OK {
			return &checks[i]
		}
	}
	return nil
}

func checkPeer(in PreflightInput) Check {
	c := Check{Name: "peer-reachable"}
	if in.PeerReachable {
		c.OK = true
		c.Detail = "the peer answered on the HA link"
		return c
	}
	c.Detail = "the peer did not answer on the HA link"
	c.Fix = "check the HA network, the link listener and `wafproxy ha status` on both nodes"
	return c
}

func checkCluster(in PreflightInput) Check {
	c := Check{Name: "cluster"}
	switch {
	case in.LocalCluster == "" || in.PeerCluster == "":
		c.Detail = "the pair record has no cluster id"
		c.Fix = "run `wafproxy ha pair` on the active and `wafproxy ha join` on the standby"
	case in.LocalCluster != in.PeerCluster:
		c.Detail = fmt.Sprintf("cluster %s does not match %s", in.LocalCluster, in.PeerCluster)
		c.Fix = "the nodes belong to different pairs; unpair the wrong one before moving traffic"
	default:
		c.OK = true
		c.Detail = "both nodes are in cluster " + in.LocalCluster
	}
	return c
}

func checkSchema(in PreflightInput) Check {
	c := Check{Name: "schema"}
	if in.LocalSchema == "" || in.PeerSchema == "" {
		c.Detail = "a node did not report its schema version"
		c.Fix = "upgrade both nodes to the same release"
		return c
	}
	if in.LocalSchema != in.PeerSchema {
		c.Detail = fmt.Sprintf("schema %s does not match %s", in.LocalSchema, in.PeerSchema)
		c.Fix = "upgrade the standby first, then the active, as the upgrade runbook describes"
		return c
	}
	c.OK = true
	c.Detail = "both nodes are at schema " + in.LocalSchema
	return c
}

func checkProtocol(in PreflightInput) Check {
	c := Check{Name: "protocol"}
	if in.LocalProtocol != in.PeerProtocol {
		c.Detail = fmt.Sprintf("link protocol %d does not match %d", in.LocalProtocol, in.PeerProtocol)
		c.Fix = "both nodes must run the same release"
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("both nodes speak protocol %d", in.LocalProtocol)
	return c
}

func checkEpoch(in PreflightInput) Check {
	c := Check{Name: "epoch"}
	if in.PeerEpoch > in.LocalEpoch {
		c.Detail = fmt.Sprintf("the peer holds epoch %d, this node %d", in.PeerEpoch, in.LocalEpoch)
		c.Fix = "this node is behind; let it sync as a standby before promoting it"
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("this node is at epoch %d, the peer at %d", in.LocalEpoch, in.PeerEpoch)
	return c
}

func checkHash(in PreflightInput) Check {
	c := Check{Name: "config-hash"}
	if in.LocalConfigHash == "" || in.PeerConfigHash == "" {
		c.Detail = "a node did not report its configuration digest"
		c.Fix = "run `wafproxy ha sync` and retry"
		return c
	}
	if in.LocalConfigHash != in.PeerConfigHash {
		c.Detail = "this node's configuration does not match the peer's"
		c.Fix = "wait for replication to catch up, or run `wafproxy ha sync` (writes may be in flight)"
		return c
	}
	c.OK = true
	c.Detail = "configuration matches the peer"
	return c
}

func checkLag(in PreflightInput) Check {
	c := Check{Name: "replication-lag"}
	if in.Lag > MaxReplicationLag {
		c.Detail = fmt.Sprintf("the copy is %s behind", in.Lag.Round(time.Millisecond))
		c.Fix = "wait for replication, check the HA network, then retry; use --force only if you accept losing the tail"
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("the copy is %s behind", in.Lag.Round(time.Millisecond))
	return c
}

func checkCertificates(in PreflightInput) Check {
	c := Check{Name: "certificates"}
	if len(in.MissingCertificates) > 0 {
		c.Detail = fmt.Sprintf("no certificate loaded for %v", in.MissingCertificates)
		c.Fix = "let ACME finish or upload the certificate before moving traffic"
		return c
	}
	c.OK = true
	c.Detail = "every enabled hostname has a certificate"
	return c
}

func checkDatabase(in PreflightInput) Check {
	c := Check{Name: "database"}
	if !in.DatabaseWritable {
		c.Detail = "the database rejected a write"
		c.Fix = "check disk space and file permissions on the data directory"
		return c
	}
	if in.QuickCheck != "" && in.QuickCheck != "ok" {
		c.Detail = "PRAGMA quick_check reported: " + in.QuickCheck
		c.Fix = "restore this node from a backup; do not move traffic to it"
		return c
	}
	c.OK = true
	c.Detail = "the database is writable and quick_check is clean"
	return c
}

func checkDisk(in PreflightInput) Check {
	c := Check{Name: "disk"}
	if in.DiskFreePercent < MinDiskFreePercent {
		c.Detail = fmt.Sprintf("%.1f%% free, below the %.0f%% floor", in.DiskFreePercent, MinDiskFreePercent)
		c.Fix = "free space on the data volume before moving traffic"
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("%.1f%% free", in.DiskFreePercent)
	return c
}

func checkSkew(in PreflightInput) Check {
	c := Check{Name: "clock-skew"}
	skew := in.ClockSkew
	if skew < 0 {
		skew = -skew
	}
	if skew > MaxClockSkew {
		c.Detail = fmt.Sprintf("clocks differ by %s", skew.Round(time.Millisecond))
		c.Fix = "fix NTP on both nodes before moving traffic"
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("clocks differ by %s", skew.Round(time.Millisecond))
	return c
}

func checkConfigWrite(in PreflightInput) Check {
	c := Check{Name: "config-write"}
	if in.ConfigWriteInFlight {
		c.Detail = "a configuration write is still in flight"
		c.Fix = "wait a moment and retry"
		return c
	}
	c.OK = true
	c.Detail = "no configuration write is in flight"
	return c
}

// Drain follows the peer's stream until this node has applied everything the
// peer holds, so a promotion starts from the newest state. It is bounded by the
// timeout and by ctx.
func Drain(ctx context.Context, dataDir string, st *store.Store, timeout time.Duration) error {
	pair, err := LoadPair(dataDir)
	if err != nil {
		return err
	}
	if pair == nil {
		return errors.New("ha: this node is not paired")
	}
	deadline := time.Now().Add(timeout)
	for {
		if _, err := SyncOnce(ctx, dataDir, st); err != nil && !errors.Is(err, ErrOutboxOverflow) {
			return err
		}
		ver, err := ConfigVersion(ctx, dataDir)
		if err != nil {
			return err
		}
		after, _, err := st.PeerAck(pair.PeerFingerprint)
		if err != nil {
			return err
		}
		if after >= ver.OutboxSeq {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("ha: the peer's stream did not drain: applied %d of %d", after, ver.OutboxSeq)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
