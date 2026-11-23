package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ha"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/version"
)

// haCLI is the operator's view of the pair. Status reads the same role file the
// data plane uses, so it cannot disagree with what the node is doing.
func haCLI(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: wafproxy ha status|pair|join|unpair|sync|failover|failback|abort|notify|ping|witness|upgrade")
	}
	switch args[0] {
	case "status":
		return haStatusCLI(args[1:])
	case "pair":
		return haPairCLI(args[1:])
	case "join":
		return haJoinCLI(args[1:])
	case "unpair":
		return haUnpairCLI(args[1:])
	case "sync":
		return haSyncCLI(args[1:])
	case "failover", "failback":
		return haMoveCLI(args[0], args[1:])
	case "abort":
		return haAbortCLI(args[1:])
	case "notify":
		return haNotifyCLI(args[1:])
	case "ping":
		return haPingCLI(args[1:])
	case "witness":
		return haWitnessCLI(args[1:])
	case "upgrade":
		return haUpgradeCLI(args[1:])
	default:
		return fmt.Errorf("unknown ha command %q (want status, pair, join, unpair, sync, failover, failback, abort or notify)", args[0])
	}
}

type haStatus struct {
	Enabled         bool            `json:"enabled"`
	Paired          bool            `json:"paired"`
	ClusterID       string          `json:"cluster_id,omitempty"`
	Role            ha.Role         `json:"role"`
	State           ha.State        `json:"state"`
	Epoch           int64           `json:"epoch"`
	Reason          string          `json:"reason,omitempty"`
	Peer            string          `json:"peer,omitempty"`
	PeerFingerprint string          `json:"peer_fingerprint,omitempty"`
	UpdatedAt       string          `json:"updated_at,omitempty"`
	Serving         bool            `json:"serving"`
	DataDir         string          `json:"data_dir"`
	Outbox          *haOutboxStatus `json:"outbox,omitempty"`
}

// haOutboxStatus is the diagnostic view of replication: what is waiting, how
// far the peer has acknowledged, and how stale that position is.
type haOutboxStatus struct {
	Depth      int64            `json:"depth"`
	Bytes      int64            `json:"bytes"`
	Pending    map[string]int64 `json:"pending_by_kind,omitempty"`
	AckedSeq   int64            `json:"acked_seq"`
	AckedAt    string           `json:"acked_at,omitempty"`
	LagSeconds float64          `json:"lag_s"`
}

// readOutboxStatus opens the database for a read. A live node keeps it open in
// WAL mode, so a second reader is safe and never blocks a write.
func readOutboxStatus(dir, peerFingerprint string) *haOutboxStatus {
	// Status must not create a database on a node that has never run.
	if _, err := os.Stat(filepath.Join(dir, "wafproxy.db")); err != nil {
		return nil
	}
	st, err := store.Open(dir)
	if err != nil {
		return nil
	}
	defer st.Close()
	stats, err := st.OutboxStats()
	if err != nil {
		return nil
	}
	out := &haOutboxStatus{Depth: stats.Depth, Bytes: stats.Bytes, Pending: stats.Pending}
	if seq, at, err := st.PeerAck(peerFingerprint); err == nil {
		out.AckedSeq = seq
		if !at.IsZero() {
			out.AckedAt = at.UTC().Format(time.RFC3339)
		}
	}
	// The active's lag is the age of the oldest unacknowledged change; the
	// standby's is how long ago it last consumed the stream.
	if stats.Depth > 0 && stats.Oldest != "" {
		if t, err := time.Parse(time.RFC3339, stats.Oldest); err == nil {
			out.LagSeconds = time.Since(t).Seconds()
		}
	} else if out.AckedAt != "" {
		if t, err := time.Parse(time.RFC3339, out.AckedAt); err == nil {
			out.LagSeconds = time.Since(t).Seconds()
		}
	}
	return out
}

// readHAStatus never fails closed to active: a damaged role file reports
// standby, exactly as the data plane would treat it.
func readHAStatus(enabled bool, dataDir string) haStatus {
	node, _ := ha.Load(dataDir) // a damaged file already loads as standby
	pair, _ := ha.LoadPair(dataDir)
	// HA off keeps an unpaired node, and a paired active, serving on its own.
	if !enabled && (pair == nil || node.Active()) {
		return haStatus{Enabled: false, Role: ha.RoleStandalone, State: ha.StateStandalone, Serving: true, DataDir: dataDir}
	}
	st := haStatus{Enabled: enabled, Role: node.Role, Epoch: node.Epoch, Reason: node.Reason, Peer: node.Peer, UpdatedAt: node.UpdatedAt, DataDir: dataDir}
	if pair != nil {
		st.Paired = true
		st.ClusterID = pair.ClusterID
		st.Peer = pair.PeerAddr
		st.PeerFingerprint = pair.PeerFingerprint
	}
	st.State = node.EffectiveState()
	st.Serving = !enabled || node.Active()
	if !enabled && st.Paired && !node.Active() {
		// The console refuses this disable, but a boot with HA off and a pair
		// on disk must not report a standby as serving.
		st.Serving = false
		st.Reason = "this node is a paired standby; it stays out of service while high availability is off"
	}
	return st
}

// haSettingFromDir reads the stored host-wide switch for the CLI. A missing
// database was never enabled, which is off.
func haSettingFromDir(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "wafproxy.db")); err != nil {
		return false
	}
	st, err := store.Open(dir)
	if err != nil {
		return false
	}
	defer st.Close()
	return haSettingOn(st)
}

func haStatusCLI(args []string) error {
	fs := flag.NewFlagSet("ha status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print one JSON object")
	watch := fs.Bool("watch", false, "refresh every second")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := dataDir()
	enabled := haSettingFromDir(dir)
	print := func() {
		st := readHAStatus(enabled, dir)
		if st.Enabled && st.Paired {
			st.Outbox = readOutboxStatus(dir, st.PeerFingerprint)
		}
		if *asJSON {
			raw, _ := json.Marshal(st)
			fmt.Println(string(raw))
			return
		}
		pair := "not paired"
		if st.Paired {
			pair = fmt.Sprintf("cluster %s peer %s", st.ClusterID, st.Peer)
		}
		line := fmt.Sprintf("role=%s state=%s serving=%v epoch=%d %s ha=%v", st.Role, st.State, st.Serving, st.Epoch, pair, st.Enabled)
		if st.Reason != "" {
			line += fmt.Sprintf(" reason=%q", st.Reason)
		}
		if st.Outbox != nil {
			line += fmt.Sprintf(" outbox=%d acked=%d lag=%s", st.Outbox.Depth, st.Outbox.AckedSeq,
				time.Duration(st.Outbox.LagSeconds*float64(time.Second)).Round(time.Second))
		}
		fmt.Println(line)
	}
	print()
	if !*watch {
		return nil
	}
	for {
		time.Sleep(time.Second)
		print()
	}
}

// haPairCLI prepares the node that will stay active: it prints the fingerprint
// the other node pins and a one-time code it must present.
func haPairCLI(args []string) error {
	fs := flag.NewFlagSet("ha pair", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := dataDir()
	id, err := ha.LoadOrCreateIdentity(dir)
	if err != nil {
		return err
	}
	// The node that issues the pairing code is the pair's active.
	if node, err := ha.Load(dir); err == nil && node.Role == ha.RoleStandalone {
		if _, err := ha.Activate(dir, node, node.Epoch); err != nil {
			return err
		}
	}
	code, err := ha.WritePairingCode(dir)
	if err != nil {
		return err
	}
	fmt.Printf("fingerprint: %s\n", ha.Fingerprint(id.Leaf))
	fmt.Printf("code:        %s\n", code)
	fmt.Println("The code expires in 10 minutes and works once.")
	link := strings.TrimSpace(os.Getenv("WAFPROXY_HA_LINK_LISTEN"))
	if link == "" {
		fmt.Println("No link address is configured; set WAFPROXY_HA_LINK_LISTEN and restart the service before joining.")
		return nil
	}
	addr := link
	if host, port, err := net.SplitHostPort(link); err == nil {
		if host == "" || host == "0.0.0.0" || host == "::" {
			addr = "<this-node-ip>:" + port
		}
	}
	fmt.Printf("On the other node run:\n  wafproxy ha join --active %s --fingerprint %s --code %s\n", addr, ha.Fingerprint(id.Leaf), code)
	return nil
}

// haJoinCLI pairs this node with an active one. The active must be running with
// its link listener up, or the connection is refused.
func haJoinCLI(args []string) error {
	fs := flag.NewFlagSet("ha join", flag.ContinueOnError)
	active := fs.String("active", "", "active node link address (host:port)")
	code := fs.String("code", "", "pairing code printed by the active node")
	pin := fs.String("fingerprint", "", "active node fingerprint printed by `ha pair`")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *active == "" || *code == "" || *pin == "" {
		return errors.New("ha join needs --active, --code and --fingerprint")
	}
	pair, err := ha.Join(context.Background(), dataDir(), *active, *pin, *code)
	if err != nil {
		return err
	}
	fmt.Printf("paired: cluster %s peer %s\n", pair.ClusterID, pair.PeerAddr)
	fmt.Println("Restart the service so the node picks up the pair.")
	return nil
}

// haSyncCLI catches up by hand. The standby daemon does this every second; the
// command exists for the first sync and for diagnosing a lagging node. A gap
// or a stream over its size limit falls back to a sealed snapshot.
// haUpgradeCLI answers whether this pair may start an upgrade. Schema and
// protocol have to match for a move; a release difference is expected halfway
// through and is reported without failing the check.
func haUpgradeCLI(args []string) error {
	fs := flag.NewFlagSet("ha upgrade", flag.ContinueOnError)
	check := fs.Bool("check", false, "report whether this pair can be upgraded")
	asJSON := fs.Bool("json", false, "print one JSON object")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*check {
		return errors.New("usage: wafproxy ha upgrade --check [--json]")
	}
	dir := dataDir()
	pair, err := ha.LoadPair(dir)
	if err != nil {
		return err
	}
	if pair == nil {
		return errors.New("this node is not paired; nothing to check")
	}
	node, err := ha.Load(dir)
	if err != nil {
		return err
	}
	local := ha.NodeVersion{Node: node.NodeID, Role: string(node.Role), Version: version.Version,
		Schema: store.SchemaVersion(), Protocol: ha.ProtocolVersion}
	var peer *ha.NodeVersion
	ping, pingErr := ha.PingPeer(context.Background(), dir)
	if pingErr == nil {
		peer = &ha.NodeVersion{Node: ping.Node, Role: string(ping.Role), Version: ping.Version,
			Schema: ping.Schema, Protocol: ping.Protocol}
	}
	report := ha.CheckUpgrade(local, peer, pingErr)
	if *asJSON {
		raw, _ := json.Marshal(report)
		fmt.Println(string(raw))
	} else {
		fmt.Printf("local: node=%s role=%s version=%s schema=%s protocol=%d\n",
			report.Local.Node, report.Local.Role, report.Local.Version, report.Local.Schema, report.Local.Protocol)
		if report.Peer != nil {
			fmt.Printf("peer:  node=%s role=%s version=%s schema=%s protocol=%d\n",
				report.Peer.Node, report.Peer.Role, report.Peer.Version, report.Peer.Schema, report.Peer.Protocol)
		}
		for _, problem := range report.Problems {
			fmt.Println("problem:", problem)
		}
		fmt.Println(report.Advice)
	}
	if !report.Compatible {
		return errors.New("this pair is not ready for a move or an upgrade")
	}
	return nil
}

func haSyncCLI(args []string) error {
	fs := flag.NewFlagSet("ha sync", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := dataDir()
	node, _ := ha.Load(dir)
	if node.Active() {
		return errors.New("refusing to overwrite this active node from its peer; run sync on the standby")
	}
	st, err := store.Open(dir)
	if err != nil {
		return err
	}
	defer st.Close()
	res, err := ha.SyncOnce(context.Background(), dir, st)
	if err != nil {
		return err
	}
	if res.Snapshot {
		fmt.Printf("stream unusable; applied a full snapshot and acknowledged seq %d\n", res.AckedSeq)
		return nil
	}
	fmt.Printf("applied %d change(s); acknowledged seq %d\n", res.Applied, res.AckedSeq)
	return nil
}

func haUnpairCLI(args []string) error {
	fs := flag.NewFlagSet("ha unpair", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := ha.Unpair(dataDir()); err != nil {
		return err
	}
	fmt.Println("unpaired. The node keeps its current role and master key; restart it so the link and pin are dropped.")
	return nil
}

func dataDir() string {
	dir := strings.TrimSpace(os.Getenv("WAFPROXY_DATA_DIR"))
	if dir == "" {
		dir = "./data"
	}
	return dir
}
