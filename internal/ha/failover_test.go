package ha

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// roleFor writes a role file for a node in the given role and epoch.
func roleFor(t *testing.T, dir string, role Role, epoch int64) *Node {
	t.Helper()
	n := &Node{NodeID: "node-a", Role: role, Epoch: epoch}
	if err := Save(dir, n); err != nil {
		t.Fatal(err)
	}
	return n
}

type moveLog struct {
	steps     []string
	resume    int
	served    bool
	demoted   bool
	rollback  int
	startRepl int
	stopRepl  int
}

func testHooks(log *moveLog, input func() PreflightInput) Hooks {
	record := func(name string) { log.steps = append(log.steps, name) }
	return Hooks{
		Preflight:   func(context.Context) (PreflightInput, error) { return input(), nil },
		QuiescePeer: func(context.Context) error { record("quiesce-peer"); return nil },
		ResumePeer:  func(context.Context) error { log.resume++; return nil },
		Drain:       func(context.Context) error { record("drain"); return nil },
		Prebind:     func(context.Context) error { record("prebind"); return nil },
		Reload:      func(context.Context) error { record("reload"); return nil },
		ReconcileBans: func(context.Context) error {
			record("reconcile-bans")
			return nil
		},
		Serve: func(context.Context) error { record("serve"); log.served = true; return nil },
		DemotePlane: func(context.Context) {
			record("demote-plane")
			log.demoted = true
		},
		OnRollback:       func() { log.rollback++ },
		StopReplication:  func() { log.stopRepl++ },
		StartReplication: func() { log.startRepl++ },
	}
}

func TestPromoteRunsTheSequenceInOrder(t *testing.T) {
	dir := t.TempDir()
	roleFor(t, dir, RoleStandby, 7)
	log := &moveLog{}
	res, err := Promote(context.Background(), dir, testHooks(log, goodPreflight), false, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"quiesce-peer", "drain", "prebind", "reload", "reconcile-bans", "serve"}
	if strings.Join(log.steps, ",") != strings.Join(want, ",") {
		t.Fatalf("step order = %v, want %v", log.steps, want)
	}
	if res.Epoch != 8 {
		t.Fatalf("result epoch = %d, want 8", res.Epoch)
	}
	node, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if node.Role != RoleActive || node.Epoch != 8 || node.EffectiveState() != StateActive {
		t.Fatalf("role file after promotion = %+v", node)
	}
	// The epoch must be on disk before the data plane serves.
	var epochAt, serveAt = -1, -1
	for i, s := range res.Steps {
		switch s.Name {
		case "epoch":
			epochAt = i
		case "serve":
			serveAt = i
		}
	}
	if epochAt < 0 || serveAt < 0 || epochAt > serveAt {
		t.Fatalf("epoch step at %d, serve at %d: %+v", epochAt, serveAt, res.Steps)
	}
}

func TestPromoteDryRunChangesNothing(t *testing.T) {
	dir := t.TempDir()
	roleFor(t, dir, RoleStandby, 2)
	log := &moveLog{}
	res, err := Promote(context.Background(), dir, testHooks(log, goodPreflight), false, true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.DryRun || len(res.Checks) != 12 || len(res.Steps) != 0 {
		t.Fatalf("dry run result = %+v", res)
	}
	if len(log.steps) != 0 || log.served || log.resume != 0 {
		t.Fatalf("a dry run had side effects: %+v", log)
	}
	node, _ := Load(dir)
	if node.Role != RoleStandby || node.Epoch != 2 {
		t.Fatalf("a dry run changed the role file: %+v", node)
	}
}

func TestPromoteRefusesOnPreflightFailure(t *testing.T) {
	dir := t.TempDir()
	roleFor(t, dir, RoleStandby, 2)
	log := &moveLog{}
	bad := goodPreflight()
	bad.DiskFreePercent = 1
	res, err := Promote(context.Background(), dir, testHooks(log, func() PreflightInput { return bad }), false, false)
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("promotion error = %v, want a BlockedError", err)
	}
	if blocked.Check.Name != "disk" || blocked.Check.Fix == "" {
		t.Fatalf("blocked check = %+v", blocked.Check)
	}
	if log.served || log.demoted {
		t.Fatal("a blocked promotion touched the data plane")
	}
	node, _ := Load(dir)
	if node.Role != RoleStandby || node.Epoch != 2 {
		t.Fatalf("a blocked promotion changed the role file: %+v", node)
	}
	if res.Epoch != 2 {
		t.Fatalf("blocked result epoch = %d", res.Epoch)
	}
}

func TestPromoteRollsBackWhenPreparationFails(t *testing.T) {
	dir := t.TempDir()
	roleFor(t, dir, RoleStandby, 2)
	log := &moveLog{}
	hooks := testHooks(log, goodPreflight)
	hooks.Prebind = func(context.Context) error { return errors.New("vip bind failed") }
	_, err := Promote(context.Background(), dir, hooks, false, false)
	if err == nil || !strings.Contains(err.Error(), "vip bind failed") {
		t.Fatalf("promotion error = %v", err)
	}
	node, _ := Load(dir)
	if node.Role != RoleStandby || node.EffectiveState() != StateStandby {
		t.Fatalf("failed promotion left role %+v", node)
	}
	// The next epoch stays on disk: a listener must never accept under an epoch
	// the node has already abandoned.
	if node.Epoch != 3 {
		t.Fatalf("rollback epoch = %d, want 3", node.Epoch)
	}
	if log.resume != 1 {
		t.Fatalf("peer resumed %d times, want 1", log.resume)
	}
	if log.served {
		t.Fatal("a failed promotion served traffic")
	}
}

func TestPromoteForceOverridesPeerQuiesce(t *testing.T) {
	dir := t.TempDir()
	roleFor(t, dir, RoleStandby, 1)
	log := &moveLog{}
	hooks := testHooks(log, goodPreflight)
	hooks.QuiescePeer = func(context.Context) error { return errors.New("peer unreachable") }
	res, err := Promote(context.Background(), dir, hooks, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Overridden) == 0 || res.Overridden[0] != "quiesce-peer" {
		t.Fatalf("overridden = %v", res.Overridden)
	}
	if !log.served {
		t.Fatal("--force did not reach serve")
	}
}

func TestPromoteAbortBeforeServe(t *testing.T) {
	dir := t.TempDir()
	roleFor(t, dir, RoleStandby, 1)
	log := &moveLog{}
	hooks := testHooks(log, goodPreflight)
	ctx, cancel := context.WithCancel(context.Background())
	hooks.Drain = func(c context.Context) error {
		cancel()
		return c.Err()
	}
	_, err := Promote(ctx, dir, hooks, false, false)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("aborted promotion error = %v", err)
	}
	node, _ := Load(dir)
	if node.Role != RoleStandby || node.Epoch != 1 {
		t.Fatalf("aborted promotion changed the role file: %+v", node)
	}
	if log.served {
		t.Fatal("an aborted promotion served traffic")
	}
	if log.resume != 1 {
		t.Fatal("an aborted promotion left the peer quiesced")
	}
}

func TestPromoteRefusesAnActiveNode(t *testing.T) {
	dir := t.TempDir()
	roleFor(t, dir, RoleActive, 4)
	log := &moveLog{}
	if _, err := Promote(context.Background(), dir, testHooks(log, goodPreflight), false, false); err == nil {
		t.Fatal("an active node promoted itself")
	}
}

func TestDemoteStepsDownAfterDraining(t *testing.T) {
	dir := t.TempDir()
	roleFor(t, dir, RoleActive, 9)
	log := &moveLog{}
	res, err := Demote(context.Background(), dir, testHooks(log, goodPreflight))
	if err != nil {
		t.Fatal(err)
	}
	if !log.demoted || log.startRepl != 1 {
		t.Fatalf("demote log = %+v", log)
	}
	node, _ := Load(dir)
	if node.Role != RoleStandby || node.EffectiveState() != StateStandby || node.Epoch != 9 {
		t.Fatalf("role file after demotion = %+v", node)
	}
	if res.Epoch != 9 {
		t.Fatalf("demote epoch = %d", res.Epoch)
	}
}

func TestBeginPromotionSurvivesACrash(t *testing.T) {
	dir := t.TempDir()
	roleFor(t, dir, RoleStandby, 5)
	node, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BeginPromotion(dir, node, 6); err != nil {
		t.Fatal(err)
	}
	// Reloading is what a restart does. The node must not come back active.
	restarted, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Active() || restarted.EffectiveState() != StatePromoting {
		t.Fatalf("restart after persisting the epoch = %+v", restarted)
	}
	if Serving(restarted.EffectiveState()) {
		t.Fatal("a promoting node reported serving")
	}
	if restarted.Epoch != 6 {
		t.Fatalf("persisted epoch = %d, want 6", restarted.Epoch)
	}
}

func TestPromoteFailsClosedWhenActivationCannotBeSaved(t *testing.T) {
	dir := t.TempDir()
	roleFor(t, dir, RoleStandby, 4)
	log := &moveLog{}
	hooks := testHooks(log, goodPreflight)
	hooks.Serve = func(context.Context) error {
		log.steps = append(log.steps, "serve")
		log.served = true
		// Make the next role write fail after listeners have accepted.
		roleDir := RoleDir(dir)
		if err := os.RemoveAll(roleDir); err != nil {
			return err
		}
		return os.WriteFile(roleDir, []byte("not a directory"), 0o600)
	}
	res, err := Promote(context.Background(), dir, hooks, false, false)
	if err == nil || !strings.Contains(err.Error(), "role file could not record") {
		t.Fatalf("promotion error = %v, want the activation failure", err)
	}
	if !log.served {
		t.Fatal("the test never reached the data plane")
	}
	if !log.demoted {
		t.Fatal("a failed activation left the data plane serving")
	}
	if log.resume != 1 {
		t.Fatalf("peer resumed %d times, want 1", log.resume)
	}
	if log.rollback != 1 {
		t.Fatalf("replication resumed %d times, want 1", log.rollback)
	}
	var activate *Step
	for i := range res.Steps {
		if res.Steps[i].Name == "activate" {
			activate = &res.Steps[i]
		}
	}
	if activate == nil || activate.OK {
		t.Fatalf("activation step = %+v, want a recorded failure", activate)
	}
}

func TestManagerAndControlSocket(t *testing.T) {
	dir := t.TempDir()
	roleFor(t, dir, RoleStandby, 3)
	log := &moveLog{}
	m := NewManager(dir, testHooks(log, goodPreflight))
	sock := ControlSocketPath(dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := ServeControl(ctx, sock, m, discardLog())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	reply, err := Control(context.Background(), sock, ControlRequest{Command: "status"})
	if err != nil || !reply.OK || reply.Status == nil {
		t.Fatalf("status reply = %+v, %v", reply, err)
	}
	if reply.Status.Role != RoleStandby || reply.Status.Epoch != 3 {
		t.Fatalf("status = %+v", reply.Status)
	}

	reply, err = Control(context.Background(), sock, ControlRequest{Command: "failover", DryRun: true})
	if err != nil || !reply.OK || reply.Result == nil || !reply.Result.DryRun {
		t.Fatalf("dry-run reply = %+v, %v", reply, err)
	}

	reply, err = Control(context.Background(), sock, ControlRequest{Command: "notify", Role: "MASTER"})
	if err != nil {
		t.Fatal(err)
	}
	if !reply.OK {
		t.Fatalf("MASTER notify refused: %s", reply.Error)
	}
	if !log.served {
		t.Fatal("MASTER notify did not serve the plane")
	}
	st := m.Status()
	if st.Role != RoleActive || st.Epoch != 4 {
		t.Fatalf("status after promotion = %+v", st)
	}

	// BACKUP now steps the node down again.
	reply, err = Control(context.Background(), sock, ControlRequest{Command: "notify", Role: "BACKUP"})
	if err != nil || !reply.OK {
		t.Fatalf("BACKUP notify = %+v, %v", reply, err)
	}
	if node, _ := Load(dir); node.Role != RoleStandby || node.Epoch != 4 {
		t.Fatalf("role after BACKUP = %+v", node)
	}

	reply, err = Control(context.Background(), sock, ControlRequest{Command: "abort"})
	if err != nil {
		t.Fatal(err)
	}
	if reply.OK || !strings.Contains(reply.Error, "no move") {
		t.Fatalf("abort with no move = %+v", reply)
	}
}

func TestControlRefusalCarriesTheCheck(t *testing.T) {
	dir := t.TempDir()
	roleFor(t, dir, RoleStandby, 1)
	bad := goodPreflight()
	bad.PeerReachable = false
	m := NewManager(dir, testHooks(&moveLog{}, func() PreflightInput { return bad }))
	sock := ControlSocketPath(dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := ServeControl(ctx, sock, m, discardLog())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	reply, err := Control(context.Background(), sock, ControlRequest{Command: "failover"})
	if err != nil {
		t.Fatal(err)
	}
	if reply.OK || reply.Blocked == nil || reply.Blocked.Name != "peer-reachable" || reply.Blocked.Fix == "" {
		t.Fatalf("refusal reply = %+v", reply)
	}
	if node, _ := Load(dir); node.Role != RoleStandby || node.Epoch != 1 {
		t.Fatalf("a refused move changed the role file: %+v", node)
	}
}

func TestManagerAbortCancelsBeforeServe(t *testing.T) {
	dir := t.TempDir()
	roleFor(t, dir, RoleStandby, 1)
	started := make(chan struct{})
	hooks := testHooks(&moveLog{}, goodPreflight)
	hooks.Drain = func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	m := NewManager(dir, hooks)
	done := make(chan error, 1)
	go func() {
		_, err := m.Failover(context.Background(), MoveOptions{})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("promotion never reached the drain step")
	}
	if err := m.Abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("aborted promotion error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("abort did not stop the promotion")
	}
	if node, _ := Load(dir); node.Role != RoleStandby {
		t.Fatalf("abort left role %+v", node)
	}
}
