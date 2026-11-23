package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ha"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// haCLI is the operator's view of the pair. Status reads the same role file the
// data plane uses, so it cannot disagree with what the node is doing.
func haCLI(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: wafproxy ha status|pair|join|unpair|sync")
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
	default:
		return fmt.Errorf("unknown ha command %q (want status, pair, join, unpair or sync)", args[0])
	}
}

type haStatus struct {
	Enabled         bool     `json:"enabled"`
	Paired          bool     `json:"paired"`
	ClusterID       string   `json:"cluster_id,omitempty"`
	Role            ha.Role  `json:"role"`
	State           ha.State `json:"state"`
	Epoch           int64    `json:"epoch"`
	Peer            string   `json:"peer,omitempty"`
	PeerFingerprint string   `json:"peer_fingerprint,omitempty"`
	UpdatedAt       string   `json:"updated_at,omitempty"`
	Serving         bool     `json:"serving"`
	DataDir         string   `json:"data_dir"`
}

// readHAStatus never fails closed to active: a damaged role file reports
// standby, exactly as the data plane would treat it.
func readHAStatus(enabled bool, dataDir string) haStatus {
	if !enabled {
		return haStatus{Enabled: false, Role: ha.RoleStandalone, State: ha.StateStandalone, Serving: true, DataDir: dataDir}
	}
	node, _ := ha.Load(dataDir) // a damaged file already loads as standby
	pair, _ := ha.LoadPair(dataDir)
	st := haStatus{Enabled: enabled, Role: node.Role, Epoch: node.Epoch, Peer: node.Peer, UpdatedAt: node.UpdatedAt, DataDir: dataDir}
	if pair != nil {
		st.Paired = true
		st.ClusterID = pair.ClusterID
		st.Peer = pair.PeerAddr
		st.PeerFingerprint = pair.PeerFingerprint
	}
	st.State = stateForRole(node.Role)
	st.Serving = !enabled || node.Active()
	return st
}

func stateForRole(r ha.Role) ha.State {
	switch r {
	case ha.RoleActive:
		return ha.StateActive
	case ha.RoleStandby:
		return ha.StateStandby
	default:
		return ha.StateStandalone
	}
}

func haStatusCLI(args []string) error {
	fs := flag.NewFlagSet("ha status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print one JSON object")
	watch := fs.Bool("watch", false, "refresh every second")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := dataDir()
	enabled := envFlag("WAFPROXY_HA_ENABLE")
	print := func() {
		st := readHAStatus(enabled, dir)
		if *asJSON {
			raw, _ := json.Marshal(st)
			fmt.Println(string(raw))
			return
		}
		pair := "not paired"
		if st.Paired {
			pair = fmt.Sprintf("cluster %s peer %s", st.ClusterID, st.Peer)
		}
		fmt.Printf("role=%s state=%s serving=%v epoch=%d %s ha=%v\n", st.Role, st.State, st.Serving, st.Epoch, pair, st.Enabled)
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

// haSyncCLI pulls one snapshot by hand. The standby daemon does this on a timer;
// the command exists for the first sync and for diagnosing a lagging node.
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
	snap, err := ha.Pull(context.Background(), dir, st)
	if err != nil {
		return err
	}
	fmt.Printf("synced schema %s snapshot %s: %d tables\n", snap.SchemaVersion, snap.CreatedAt, len(snap.Tables))
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

func envFlag(name string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	return v == "1" || v == "true" || v == "yes"
}
