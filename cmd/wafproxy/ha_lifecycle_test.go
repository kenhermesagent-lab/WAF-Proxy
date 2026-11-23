package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/config"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ha"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func TestHABootOnNeedsTheBootSwitchAndTheSetting(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	on := &config.Config{HAEnabled: true}

	if haBootOn(on, st) {
		t.Fatal("a missing ha_enabled must boot as a single node")
	}
	if err := st.SetSettings(map[string]string{"ha_enabled": "1"}); err != nil {
		t.Fatal(err)
	}
	if !haBootOn(on, st) {
		t.Fatal("boot switch and setting both on must run HA")
	}
	if err := st.SetSettings(map[string]string{"ha_enabled": "0"}); err != nil {
		t.Fatal(err)
	}
	if haBootOn(on, st) {
		t.Fatal("ha_enabled=0 must boot as a single node")
	}
	if err := st.SetSettings(map[string]string{"ha_enabled": "1"}); err != nil {
		t.Fatal(err)
	}
	if haBootOn(&config.Config{}, st) {
		t.Fatal("WAFPROXY_HA_ENABLE=0 must win over the setting")
	}
}

func TestHABootRoleKeepsAPairedStandbyOutOfService(t *testing.T) {
	dir := t.TempDir()
	standby := &ha.Node{NodeID: "node-b", Role: ha.RoleStandby, State: ha.StateStandby, Epoch: 2}
	if err := ha.Save(dir, standby); err != nil {
		t.Fatal(err)
	}
	got, err := haBootRole(dir, standby, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Active() || got.Role != ha.RoleStandby {
		t.Fatalf("a paired standby became %+v with HA off", got)
	}
	unpaired, err := haBootRole(dir, got, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !unpaired.Active() || unpaired.Role != ha.RoleStandalone {
		t.Fatalf("an unpaired standby became %+v with HA off", unpaired)
	}
}

func TestHARuntimeStartsAndStopsLive(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := ha.Save(dir, &ha.Node{NodeID: "node-a", Role: ha.RoleStandalone, Epoch: 3}); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()
	rt := &haRuntime{
		root: ctx, dir: dir, st: st, quiesce: ha.NewQuiesce(), log: log,
		repl: newReplicator(ctx, dir, st, log),
	}

	rt.Stop() // turning off what never started is a no-op
	rt.Start()
	if !rt.started {
		t.Fatal("Start did not mark the runtime running")
	}
	rt.Start() // idempotent
	rt.Stop()
	if rt.started {
		t.Fatal("Stop did not mark the runtime stopped")
	}
	rt.Start() // and it can be turned back on without a restart
	if !rt.started {
		t.Fatal("second Start did not run the runtime")
	}
	rt.Stop()
}
