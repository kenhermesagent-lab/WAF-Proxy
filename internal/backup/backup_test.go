package backup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"log/slog"

	"golang.org/x/crypto/ssh"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func TestValidateRejectsIncompleteDestinations(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"no transport", Config{Keep: 7}, "choose a backup destination"},
		{"relative dir", Config{Transport: "local", LocalDir: "backups", Keep: 7}, "absolute path"},
		{"sftp without host key", Config{Transport: "sftp", Host: "h", Port: 22, User: "u", Keep: 7}, "host key"},
		{"bad time", Config{Transport: "local", LocalDir: "/tmp/x", Time: "3am", Keep: 7}, "HH:MM"},
		{"bad keep", Config{Transport: "local", LocalDir: "/tmp/x", Keep: 0}, "keep"},
		{"bad daily time", Config{Transport: "local", LocalDir: "/tmp/x", Keep: 7, DailyTime: "3am"}, "daily run time"},
		{"bad daily keep", Config{Transport: "local", LocalDir: "/tmp/x", Keep: 7, DailyEnabled: true, DailyKeep: 0}, "daily copies"},
	}
	for _, tc := range cases {
		if got := tc.cfg.Validate(); got == "" || !strings.Contains(got, tc.want) {
			t.Errorf("%s: got %q, want a message containing %q", tc.name, got, tc.want)
		}
	}
}

func TestValidateAcceptsAFullConfig(t *testing.T) {
	c := Config{Transport: "sftp", Host: "backup.example.com", Port: 22, User: "u", HostKey: "abc", Keep: 7, Time: "03:00"}
	if msg := c.Validate(); msg != "" {
		t.Fatalf("unexpected rejection: %s", msg)
	}
}

func TestWriteLocalPrunesOldFiles(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "wafproxy-backup-20240101-000000.json")
	if err := os.WriteFile(old, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeLocal(discardLog(), dir, fullPrefix, "wafproxy-backup-20240102-000000.json", []byte("{}"), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("old backup was not pruned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "wafproxy-backup-20240102-000000.json")); err != nil {
		t.Fatalf("new backup missing: %v", err)
	}
}

// The daily copies have their own file names and their own keep count, so a
// daily run never deletes a weekly copy.
func TestDailyTierPrunesOnlyItsOwnFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("wafproxy-backup-20240101-030000.json")
	write("wafproxy-daily-20240101-030000.json")
	write("wafproxy-daily-20240102-030000.json")
	if err := writeLocal(discardLog(), dir, dailyPrefix, "wafproxy-daily-20240103-030000.json", []byte("{}\n"), 2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "wafproxy-daily-20240101-030000.json")); !os.IsNotExist(err) {
		t.Fatalf("the oldest daily copy was not pruned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "wafproxy-backup-20240101-030000.json")); err != nil {
		t.Fatalf("the daily prune removed a scheduled copy: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "wafproxy-daily-20240102-030000.json")); err != nil {
		t.Fatalf("a daily copy inside the keep count is missing: %v", err)
	}
}

func TestRunDailyWritesDailyFilesAndKeepsItsCount(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	box, err := crypto.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	clock := time.Date(2026, 3, 2, 3, 0, 0, 0, time.UTC)
	m := New(st, box, slog.New(slog.NewTextHandler(io.Discard, nil)), func() ([]byte, error) { return []byte("{}\n"), nil })
	m.now = func() time.Time { return clock }
	saved := Config{Transport: "local", LocalDir: dir, Schedule: "weekly", Time: "03:00", Keep: 2,
		DailyEnabled: true, DailyTime: "03:30", DailyKeep: 2}
	if err := m.Save(saved); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		status, err := m.RunDaily()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(status.LastDailyFile, dailyPrefix) {
			t.Fatalf("daily file = %q", status.LastDailyFile)
		}
		clock = clock.Add(24 * time.Hour)
	}
	if _, err := m.RunNow(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	daily, full := 0, 0
	for _, e := range entries {
		switch {
		case strings.HasPrefix(e.Name(), dailyPrefix):
			daily++
		case strings.HasPrefix(e.Name(), fullPrefix):
			full++
		}
	}
	if daily != 2 || full != 1 {
		t.Fatalf("kept %d daily and %d scheduled files, want 2 and 1", daily, full)
	}
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// A prune that fails after the copy is on disk must not turn a good backup into
// a failed run: the file is reported as written and the old copy stays.
func TestPruneFailureStillReportsTheFileWritten(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "wafproxy-backup-20240101-000000.json")
	if err := os.WriteFile(old, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := removeFile
	removeFile = func(string) error { return errors.New("permission denied") }
	defer func() { removeFile = previous }()

	m := testManager(t, func() ([]byte, error) { return []byte("{}\n"), nil })
	m.now = func() time.Time { return time.Date(2026, 3, 1, 3, 0, 0, 0, time.UTC) }
	if err := m.Save(Config{Transport: "local", LocalDir: dir, Schedule: "daily", Time: "03:00", Keep: 1}); err != nil {
		t.Fatal(err)
	}
	status, err := m.RunNow()
	if err != nil {
		t.Fatalf("a prune failure failed the run: %v", err)
	}
	if status.LastFile == "" || status.LastError != "" {
		t.Fatalf("status = %+v, want the file reported and no error", status)
	}
	if _, err := os.Stat(filepath.Join(dir, status.LastFile)); err != nil {
		t.Fatalf("the copy reported as written is missing: %v", err)
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatalf("the copy the prune could not delete vanished: %v", err)
	}
}

// A remote listing or delete that fails is a warning, not a failed backup.
func TestRemotePruneFailureIsOnlyAWarning(t *testing.T) {
	var log bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&log, nil))

	pruneRemote(logger, "sftp", &fakeRemoteDir{namesErr: errors.New("LIST denied")}, fullPrefix, 1)
	pruneRemote(logger, "ftp", &fakeRemoteDir{
		namesOut:  []string{"wafproxy-backup-20240101-000000.json", "wafproxy-backup-20240102-000000.json"},
		removeErr: errors.New("DELE denied"),
	}, fullPrefix, 1)

	if got := strings.Count(log.String(), "backup prune failed"); got != 2 {
		t.Fatalf("logged %d prune warnings, want 2: %s", got, log.String())
	}
}

// The happy path still deletes the oldest remote copy of the tier.
func TestRemotePruneDeletesTheOldestCopy(t *testing.T) {
	dir := &fakeRemoteDir{namesOut: []string{
		"wafproxy-backup-20240101-000000.json",
		"wafproxy-backup-20240102-000000.json",
		"wafproxy-daily-20240101-000000.json",
	}}
	pruneRemote(discardLog(), "sftp", dir, fullPrefix, 1)
	if len(dir.removed) != 1 || dir.removed[0] != "wafproxy-backup-20240101-000000.json" {
		t.Fatalf("removed %v, want only the oldest scheduled copy", dir.removed)
	}
}

type fakeRemoteDir struct {
	namesOut  []string
	namesErr  error
	removeErr error
	removed   []string
}

func (d *fakeRemoteDir) names() ([]string, error) { return d.namesOut, d.namesErr }

func (d *fakeRemoteDir) remove(name string) error {
	if d.removeErr != nil {
		return d.removeErr
	}
	d.removed = append(d.removed, name)
	return nil
}

func testManager(t *testing.T, produce func() ([]byte, error)) *Manager {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	box, err := crypto.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return New(st, box, slog.New(slog.NewTextHandler(io.Discard, nil)), produce)
}

// The daily time defaults to the weekly one, so both tiers fall due in the same
// minute and both files must appear.
func TestBothTiersWriteWhenTheirTimesCoincide(t *testing.T) {
	dir := t.TempDir()
	m := testManager(t, func() ([]byte, error) { return []byte("{}\n"), nil })
	if err := m.Save(Config{Transport: "local", LocalDir: dir, Schedule: "weekly", Weekday: 0, Time: "03:00",
		Keep: 2, DailyEnabled: true, DailyTime: "03:00", DailyKeep: 7}); err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return time.Date(2026, 3, 1, 3, 0, 0, 0, time.UTC) }

	full, daily := m.runDue(true, true)
	if full == "" || daily == "" {
		t.Fatalf("runDue wrote %q and %q, want one file per tier", full, daily)
	}
	if !strings.HasPrefix(full, fullPrefix) || !strings.HasPrefix(daily, dailyPrefix) {
		t.Fatalf("files = %q and %q", full, daily)
	}
	for _, name := range []string{full, daily} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s was not written: %v", name, err)
		}
	}
}

// A tier that comes due while another run holds the lock waits for it instead
// of being refused, so the copy is not lost for the whole period.
func TestScheduledTierWaitsForARunInFlight(t *testing.T) {
	dir := t.TempDir()
	m := testManager(t, func() ([]byte, error) { return []byte("{}\n"), nil })
	if err := m.Save(Config{Transport: "local", LocalDir: dir, Schedule: "weekly", Time: "03:00",
		Keep: 2, DailyEnabled: true, DailyKeep: 7}); err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return time.Date(2026, 3, 1, 3, 0, 0, 0, time.UTC) }

	m.runMu.Lock()
	done := make(chan [2]string, 1)
	go func() {
		full, daily := m.runDue(true, true)
		done <- [2]string{full, daily}
	}()
	// Let the goroutine reach the lock before the simulated run releases it.
	time.Sleep(20 * time.Millisecond)
	m.runMu.Unlock()

	got := <-done
	if got[0] == "" || got[1] == "" {
		t.Fatalf("queued run wrote %q and %q, want both", got[0], got[1])
	}
	for _, name := range got {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s was not written: %v", name, err)
		}
	}
}

// A daily run reports itself under the daily fields and leaves the scheduled
// tier's last run alone, so the console never names one file twice.
func TestDailyRunLeavesTheScheduledLastRunAlone(t *testing.T) {
	dir := t.TempDir()
	m := testManager(t, func() ([]byte, error) { return []byte("{}\n"), nil })
	clock := time.Date(2026, 3, 1, 3, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return clock }
	if err := m.Save(Config{Transport: "local", LocalDir: dir, Schedule: "weekly", Time: "03:00",
		Keep: 2, DailyEnabled: true, DailyTime: "04:00", DailyKeep: 7}); err != nil {
		t.Fatal(err)
	}
	scheduled, err := m.RunNow()
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Hour)
	daily, err := m.RunDaily()
	if err != nil {
		t.Fatal(err)
	}
	if daily.LastDailyFile == "" || daily.LastDailyFile == scheduled.LastFile {
		t.Fatalf("daily status = %+v", daily)
	}
	if daily.LastFile != scheduled.LastFile {
		t.Fatalf("the daily run replaced the scheduled last file: %q -> %q", scheduled.LastFile, daily.LastFile)
	}
	if daily.LastTarget != scheduled.LastTarget {
		t.Fatalf("the daily run replaced the scheduled target: %q -> %q", scheduled.LastTarget, daily.LastTarget)
	}
	if !strings.HasSuffix(daily.LastDailyTarget, daily.LastDailyFile) {
		t.Fatalf("daily target %q does not name %q", daily.LastDailyTarget, daily.LastDailyFile)
	}
}

// A failed scheduled run must leave its slot pending for the next tick, and the
// slot must eventually be released so a dead destination is not retried forever.
func TestFailedRunKeepsItsSlotForARetry(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	due := time.Date(2026, 3, 1, 3, 0, 0, 0, time.UTC)
	if got := clearSlot(log, due, "", due.Add(time.Minute)); !got.Equal(due) {
		t.Fatalf("a failed run cleared its slot: %v", got)
	}
	if got := clearSlot(log, due, "wafproxy-backup-20260301-030000.json", due); !got.IsZero() {
		t.Fatalf("a written file did not clear its slot: %v", got)
	}
	if got := clearSlot(log, due, "", due.Add(retryFor+time.Minute)); !got.IsZero() {
		t.Fatalf("a slot older than the retry window was kept: %v", got)
	}
}

// Start's own loop is where a copy was lost: a failed tick must leave the slot
// pending, and the next tick must write both tiers, once each.
func TestStartRetriesAPendingSlot(t *testing.T) {
	dir := t.TempDir()
	var failMu sync.Mutex
	failing := true
	m := testManager(t, func() ([]byte, error) {
		failMu.Lock()
		defer failMu.Unlock()
		if failing {
			return nil, errors.New("destination down")
		}
		return []byte("{}\n"), nil
	})

	var clockMu sync.Mutex
	now := time.Date(2026, 3, 1, 3, 0, 0, 0, time.UTC) // Sunday
	m.now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	if err := m.Save(Config{Transport: "local", LocalDir: dir, Schedule: "weekly", Weekday: 0, Time: "03:00",
		Keep: 2, DailyEnabled: true, DailyTime: "03:00", DailyKeep: 7, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	ticks := make(chan time.Time)
	m.ticks = ticks
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { m.Start(ctx); close(done) }()

	ticks <- now
	waitFor(t, "the failed attempt", func() bool { return m.Status().LastError != "" })
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("a failed run left files %v (%v)", entries, err)
	}

	failMu.Lock()
	failing = false
	failMu.Unlock()
	clockMu.Lock()
	now = now.Add(time.Minute)
	clockMu.Unlock()
	ticks <- now
	waitFor(t, "the retry to write both tiers", func() bool {
		entries, err := os.ReadDir(dir)
		return err == nil && len(entries) == 2
	})
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	full, daily := 0, 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), fullPrefix) {
			full++
		}
		if strings.HasPrefix(e.Name(), dailyPrefix) {
			daily++
		}
	}
	if full != 1 || daily != 1 {
		t.Fatalf("wrote %d scheduled and %d daily files, want one of each", full, daily)
	}

	// The spent slots must not run again on the next tick.
	ticks <- now
	time.Sleep(50 * time.Millisecond)
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 2 {
		t.Fatalf("an idle tick wrote again: %v (%v)", entries, err)
	}

	cancel()
	<-done
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The console's "Back up now" still reports busy rather than blocking.
func TestManualRunReportsBusy(t *testing.T) {
	m := testManager(t, func() ([]byte, error) { return []byte("{}\n"), nil })
	m.runMu.Lock()
	defer m.runMu.Unlock()
	if _, err := m.RunNow(); !errors.Is(err, errBusy) {
		t.Fatalf("manual run while busy = %v, want %v", err, errBusy)
	}
}

// A local destination saved without a port must read back as SFTP's default,
// or switching the transport later fails validation with a port of zero.
func TestConfigDefaultsTheRemotePort(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	box, err := crypto.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	m := New(st, box, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err := m.Save(Config{Transport: "local", LocalDir: "/tmp/backups", Keep: 3, Time: "03:00"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := m.Config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 22 {
		t.Fatalf("port = %d, want 22", cfg.Port)
	}
}

func TestNextRunDailyRollsForward(t *testing.T) {
	local := time.FixedZone("UTC+0", 0)
	now := time.Date(2026, 3, 2, 4, 0, 0, 0, local)
	next, ok := nextRun(Config{Enabled: true, Schedule: "daily", Time: "03:00"}, now)
	if !ok {
		t.Fatal("expected a scheduled run")
	}
	if want := time.Date(2026, 3, 3, 3, 0, 0, 0, local); !next.Equal(want) {
		t.Fatalf("next run = %s, want %s", next, want)
	}
	if _, ok := nextRun(Config{Enabled: false, Schedule: "daily", Time: "03:00"}, now); ok {
		t.Fatal("a disabled schedule must not report a next run")
	}
}

// The daily tier is a day ahead even when the primary schedule is weekly, so
// both schedules can be due on the same day and each writes its own file.
func TestNextDailyRunIgnoresTheWeeklyDay(t *testing.T) {
	now := time.Date(2026, 3, 2, 4, 0, 0, 0, time.UTC)
	next, ok := nextDailyRun(Config{Enabled: true, Schedule: "weekly", Time: "03:00", Weekday: 0,
		DailyEnabled: true, DailyTime: "03:30", DailyKeep: 7}, now)
	if !ok {
		t.Fatal("expected a daily run")
	}
	if want := time.Date(2026, 3, 3, 3, 30, 0, 0, time.UTC); !next.Equal(want) {
		t.Fatalf("next daily = %s, want %s", next, want)
	}
	if _, ok := nextDailyRun(Config{Enabled: true, Schedule: "weekly", Time: "03:00"}, now); ok {
		t.Fatal("a disabled daily tier must not report a next run")
	}
}

func TestParseFingerprintRejectsAMismatch(t *testing.T) {
	cb, err := parseFingerprint("SHA256:wanted")
	if err != nil {
		t.Fatal(err)
	}
	if err := cb("host", nil, testKey{}); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected a mismatch, got %v", err)
	}
}

type testKey struct{}

func (testKey) Type() string                        { return "ssh-ed25519" }
func (testKey) Marshal() []byte                     { return nil }
func (testKey) Verify([]byte, *ssh.Signature) error { return nil }
