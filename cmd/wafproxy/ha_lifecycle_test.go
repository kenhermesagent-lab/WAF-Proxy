package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ha"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func TestHASettingDrivesTheBoot(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if haSettingOn(st) {
		t.Fatal("a missing ha_enabled must boot as a single node")
	}
	if err := st.SetSettings(map[string]string{"ha_enabled": "1"}); err != nil {
		t.Fatal(err)
	}
	if !haSettingOn(st) {
		t.Fatal("ha_enabled=1 must boot with HA on")
	}
	if err := st.SetSettings(map[string]string{"ha_enabled": "0"}); err != nil {
		t.Fatal(err)
	}
	if haSettingOn(st) {
		t.Fatal("ha_enabled=0 must boot as a single node")
	}
}

func TestFreshInstallServesWithHAAff(t *testing.T) {
	dir := t.TempDir()
	// The identity gives the fresh role file the node id the standalone record
	// needs; boot must create it before normalising the role.
	if _, err := ha.LoadOrCreateIdentity(dir); err != nil {
		t.Fatal(err)
	}
	node, err := ha.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := haBootRole(dir, node, false, false)
	if err != nil {
		t.Fatalf("fresh boot could not become standalone: %v", err)
	}
	if !got.Active() || got.Role != ha.RoleStandalone {
		t.Fatalf("a fresh node with HA off became %+v; want it serving alone", got)
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

func TestHARuntimeDoesNotStartWithoutTheControlSocket(t *testing.T) {
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
	sock := ha.ControlSocketPath(dir)
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		t.Fatal(err)
	}
	live, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}

	if err := rt.Start(); err == nil || !strings.Contains(err.Error(), "control socket") {
		t.Fatalf("Start with a live control socket = %v, want a bind error", err)
	}
	if rt.started || rt.usable() {
		fatal := "started"
		if !rt.started {
			fatal = "usable"
		}
		t.Fatalf("a failed start left the runtime %s", fatal)
	}
	failure := rt.runtimeFailure()
	if failure == nil || !strings.Contains(failure.Error(), "control socket") {
		t.Fatalf("runtime failure = %v, want the control-socket reason", failure)
	}
	if _, err := (haControl{rt: rt}).manager(); err == nil || !strings.Contains(err.Error(), failure.Error()) {
		t.Fatalf("move refusal = %v, want it to carry %q", err, failure)
	}

	// Releasing the path lets the same runtime start normally.
	_ = live.Close()
	_ = os.Remove(sock)
	if err := rt.Start(); err != nil {
		t.Fatalf("Start after the socket was released: %v", err)
	}
	if rt.runtimeFailure() != nil {
		t.Fatalf("a successful start still reports %v", rt.runtimeFailure())
	}
	rt.Stop()
}

// A fresh install has neither a role file nor a node id. With HA off it must
// boot serving as a single node, not hold the WAN address as a standby.
func TestHABootRoleServesAFreshSingleNode(t *testing.T) {
	dir := t.TempDir()
	node, err := ha.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := haBootRole(dir, node, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Active() || got.Role != ha.RoleStandalone {
		t.Fatalf("a fresh node booted as %+v with HA off", got)
	}
	saved, err := ha.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !saved.Active() {
		t.Fatalf("the role file on disk leaves a fresh node out of service: %+v", saved)
	}
}

func TestHADisableRefusalFollowsTheRoleAndTypedID(t *testing.T) {
	active := &ha.Node{Role: ha.RoleActive}
	standby := &ha.Node{Role: ha.RoleStandby}
	pair := &ha.Pair{ClusterID: "cluster-abc"}

	if got := haDisableRefusal(active, nil, ""); got != "" {
		t.Fatalf("an unpaired node was refused: %s", got)
	}
	if got := haDisableRefusal(active, pair, ""); got == "" {
		t.Fatal("a paired active node was allowed without the cluster id")
	}
	if got := haDisableRefusal(active, pair, "wrong"); got == "" {
		t.Fatal("a wrong cluster id was accepted")
	}
	if got := haDisableRefusal(active, pair, "cluster-abc"); got != "" {
		t.Fatalf("the right cluster id was refused: %s", got)
	}
	if got := haDisableRefusal(standby, pair, "cluster-abc"); got == "" {
		t.Fatal("a paired standby was allowed to disable even with the cluster id")
	}
}

func TestHADisableIsRefusedWhenTheRoleOrPairCannotBeRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(ha.RoleDir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	rt := &haRuntime{}

	// The settings save reaches this callback, so a refusal here is the save
	// being refused. A broken role record must not read as "standalone".
	role := filepath.Join(ha.RoleDir(dir), "node.json")
	if err := os.WriteFile(role, []byte("{truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := haApplyChange(rt, dir, false, ""); err == nil {
		t.Fatal("a disable was allowed with an unreadable role")
	}

	// A readable active role with a broken pair record is refused too: the
	// cluster id cannot be checked, so the node must not stop on its own.
	if err := ha.Save(dir, &ha.Node{NodeID: "node-a", Role: ha.RoleActive, Epoch: 4}); err != nil {
		t.Fatal(err)
	}
	pair := filepath.Join(ha.RoleDir(dir), "pair.json")
	if err := os.WriteFile(pair, []byte("{truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := haApplyChange(rt, dir, false, ""); err == nil {
		t.Fatal("a disable was allowed with an unreadable pair")
	}
}

func TestHAUpgradeCheckNeedsAPair(t *testing.T) {
	t.Setenv("WAFPROXY_DATA_DIR", t.TempDir())
	if err := haUpgradeCLI([]string{}); err == nil || !strings.Contains(err.Error(), "--check") {
		t.Fatalf("no flag = %v, want the usage error", err)
	}
	if err := haUpgradeCLI([]string{"--check"}); err == nil || !strings.Contains(err.Error(), "not paired") {
		t.Fatalf("unpaired = %v, want the pairing error", err)
	}
}

func TestHASyncRefusesTheActive(t *testing.T) {
	dir := t.TempDir()
	if err := ha.Save(dir, &ha.Node{NodeID: "node-a", Role: ha.RoleActive, Epoch: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := (haControl{dir: dir}).Sync(context.Background()); err == nil {
		t.Fatal("sync on the active was allowed to replace it from its peer")
	}
}

func TestHASettingFromDirFollowsTheStoredSwitch(t *testing.T) {
	dir := t.TempDir()
	if haSettingFromDir(dir) {
		t.Fatal("a missing database reported HA on")
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetSettings(map[string]string{"ha_enabled": "1"}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if !haSettingFromDir(dir) {
		t.Fatal("ha_enabled=1 was not read from the database")
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
