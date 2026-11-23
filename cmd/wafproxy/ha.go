package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ha"
)

// haCLI is the operator's view of the pair. Status reads the same role file the
// data plane uses, so it cannot disagree with what the node is doing.
func haCLI(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: wafproxy ha status [--json] [--watch]")
	}
	switch args[0] {
	case "status":
		return haStatusCLI(args[1:])
	default:
		return fmt.Errorf("unknown ha command %q (want status)", args[0])
	}
}

type haStatus struct {
	Enabled   bool     `json:"enabled"`
	Paired    bool     `json:"paired"`
	Role      ha.Role  `json:"role"`
	State     ha.State `json:"state"`
	Epoch     int64    `json:"epoch"`
	Peer      string   `json:"peer,omitempty"`
	UpdatedAt string   `json:"updated_at,omitempty"`
	Serving   bool     `json:"serving"`
	DataDir   string   `json:"data_dir"`
}

// readHAStatus never fails closed to active: a damaged role file reports
// standby, exactly as the data plane would treat it.
func readHAStatus(enabled bool, dataDir string) haStatus {
	if !enabled {
		return haStatus{Enabled: false, Role: ha.RoleStandalone, State: ha.StateStandalone, Serving: true, DataDir: dataDir}
	}
	node, _ := ha.Load(dataDir) // a damaged file already loads as standby
	st := haStatus{Enabled: enabled, Role: node.Role, Epoch: node.Epoch, Peer: node.Peer, UpdatedAt: node.UpdatedAt, DataDir: dataDir}
	st.Paired = node.NodeID != "" && node.Peer != ""
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
	dir := os.Getenv("WAFPROXY_DATA_DIR")
	if strings.TrimSpace(dir) == "" {
		dir = "./data"
	}
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
			pair = "peer " + st.Peer
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

func envFlag(name string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	return v == "1" || v == "true" || v == "yes"
}
