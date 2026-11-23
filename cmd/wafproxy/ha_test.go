package main

import (
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ha"
)

func TestReadHAStatusFailClosed(t *testing.T) {
	dir := t.TempDir()
	st := readHAStatus(true, dir)
	if st.Role != ha.RoleStandby || st.State != ha.StateStandby || st.Serving {
		t.Fatalf("missing role file = %+v; want standby and not serving", st)
	}
	if st.Paired {
		t.Fatal("an unpaired node reported a pair")
	}

	node := &ha.Node{NodeID: "node-a", Role: ha.RoleActive, Epoch: 4, Peer: "10.0.0.11:9443"}
	if err := ha.Save(dir, node); err != nil {
		t.Fatal(err)
	}
	st = readHAStatus(true, dir)
	if !st.Serving || st.State != ha.StateActive || st.Epoch != 4 || !st.Paired {
		t.Fatalf("active role = %+v", st)
	}

	// With HA off the same file must not stop a single node serving.
	st = readHAStatus(false, dir)
	if !st.Serving || st.State != ha.StateStandalone {
		t.Fatalf("HA off = %+v; want standalone and serving", st)
	}
}
