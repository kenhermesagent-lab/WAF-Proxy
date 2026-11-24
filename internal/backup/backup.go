// Package backup writes the console's configuration export to a local
// directory, a git repository, SFTP or FTP on a schedule.
package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jlaffaye/ftp"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// Config is the persisted backup schedule and destination.
type Config struct {
	Enabled   bool   `json:"enabled"`
	Transport string `json:"transport"` // local | git | sftp | ftp
	Schedule  string `json:"schedule"`  // daily | weekly
	Time      string `json:"time"`      // HH:MM, 24-hour
	Weekday   int    `json:"weekday"`   // 0 = Sunday
	// Keep is how many files the schedule above retains. A weekly schedule with
	// 52 keeps a year of full copies.
	Keep int `json:"keep"`

	// DailyEnabled adds a second copy every day, written to its own file names
	// and pruned by DailyKeep alone, so last week's copies age out on their own
	// without touching the weekly ones.
	DailyEnabled bool   `json:"daily_enabled"`
	DailyTime    string `json:"daily_time"` // HH:MM; empty uses Time
	DailyKeep    int    `json:"daily_keep"`

	LocalDir  string `json:"local_dir"`
	GitDir    string `json:"git_dir"`
	GitRemote string `json:"git_remote"`
	GitBranch string `json:"git_branch"`

	Host        string `json:"host"`
	Port        int    `json:"port"`
	User        string `json:"user"`
	Dir         string `json:"dir"`
	HostKey     string `json:"host_key"` // SHA256 fingerprint, required for SFTP
	Password    string `json:"password,omitempty"`
	HasPassword bool   `json:"has_password"`

	// Encrypt wraps each written file in AES-256-GCM under Passphrase, which is
	// stored sealed and never returned by the API.
	Encrypt       bool   `json:"encrypt"`
	Passphrase    string `json:"passphrase,omitempty"`
	HasPassphrase bool   `json:"has_passphrase"`
}

// Status is the last run, reported to the console.
type Status struct {
	LastRun    string `json:"last_run,omitempty"`
	LastError  string `json:"last_error,omitempty"`
	LastFile   string `json:"last_file,omitempty"`
	LastTarget string `json:"last_target,omitempty"`
	NextRun    string `json:"next_run,omitempty"`

	LastDailyRun  string `json:"last_daily_run,omitempty"`
	LastDailyFile string `json:"last_daily_file,omitempty"`
	NextDailyRun  string `json:"next_daily_run,omitempty"`
}

// Prefixes keep the two tiers in separate file names, so each prunes only its
// own copies.
const (
	fullPrefix  = "wafproxy-backup-"
	dailyPrefix = "wafproxy-daily-"
)

var branchRE = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,80}$`)

// Validate rejects a configuration the transport cannot honour.
func (c Config) Validate() string {
	switch c.Transport {
	case "local":
		if c.LocalDir == "" || !filepath.IsAbs(c.LocalDir) {
			return "the backup directory must be an absolute path"
		}
	case "git":
		if c.GitDir == "" || !filepath.IsAbs(c.GitDir) {
			return "the git working directory must be an absolute path"
		}
		if c.GitBranch != "" && !branchRE.MatchString(c.GitBranch) {
			return "the git branch name is not valid"
		}
	case "sftp", "ftp":
		if strings.TrimSpace(c.Host) == "" {
			return "a remote host is required"
		}
		if c.Port < 1 || c.Port > 65535 {
			return "the remote port must be 1-65535"
		}
		if strings.TrimSpace(c.User) == "" {
			return "a remote user is required"
		}
		if strings.ContainsAny(c.Dir, "\r\n\x00") {
			return "the remote path contains a control character"
		}
		if c.Transport == "sftp" && strings.TrimSpace(c.HostKey) == "" {
			return "an SSH host key fingerprint is required; run ssh-keyscan and paste the SHA256 fingerprint"
		}
	default:
		return "choose a backup destination"
	}
	if c.Schedule != "" && c.Schedule != "daily" && c.Schedule != "weekly" {
		return "the schedule must be daily or weekly"
	}
	if c.Time != "" {
		if _, err := time.Parse("15:04", c.Time); err != nil {
			return "the run time must be HH:MM"
		}
	}
	if c.Weekday < 0 || c.Weekday > 6 {
		return "the weekday must be 0-6"
	}
	if c.Keep < 1 || c.Keep > 365 {
		return "keep 1-365 backups"
	}
	if c.DailyTime != "" {
		if _, err := time.Parse("15:04", c.DailyTime); err != nil {
			return "the daily run time must be HH:MM"
		}
	}
	if c.DailyEnabled && (c.DailyKeep < 1 || c.DailyKeep > 365) {
		return "keep 1-365 daily copies"
	}
	if c.Encrypt && c.Passphrase == "" && !c.HasPassphrase {
		return "an encryption passphrase is required"
	}
	if c.Passphrase != "" && len(c.Passphrase) < 16 {
		return "the encryption passphrase must be at least 16 characters"
	}
	return ""
}

// Manager schedules and performs backups.
type Manager struct {
	st      *store.Store
	box     *crypto.Box
	log     *slog.Logger
	produce func() ([]byte, error)
	now     func() time.Time

	mu     sync.Mutex
	status Status
	// runMu serialises writes. A manual run takes it without waiting and reports
	// busy; the scheduler waits for it, so two tiers due in the same minute both
	// write their file instead of one being dropped.
	runMu sync.Mutex
	// ticks drives Start; nil means a one-minute ticker. Tests install their own
	// channel to schedule several minutes without waiting.
	ticks <-chan time.Time
}

// errBusy is returned to a manual run while another backup is in flight.
var errBusy = errors.New("a backup is already running")

// New returns a manager. produce renders the backup document.
func New(st *store.Store, box *crypto.Box, log *slog.Logger, produce func() ([]byte, error)) *Manager {
	return &Manager{st: st, box: box, log: log, produce: produce, now: time.Now}
}

// settings maps the store keys onto Config.
func (m *Manager) Config() (Config, error) {
	kv, err := m.st.Settings()
	if err != nil {
		return Config{}, err
	}
	get := func(key string) string { return strings.TrimSpace(kv[key]) }
	atoi := func(key string, fallback int) int {
		if n, err := strconv.Atoi(get(key)); err == nil {
			return n
		}
		return fallback
	}
	c := Config{
		Enabled:   get("backup_enabled") == "1",
		Transport: get("backup_transport"),
		Schedule:  get("backup_schedule"),
		Time:      get("backup_time"),
		Weekday:   atoi("backup_weekday", 0),
		Keep:      atoi("backup_keep", 7),

		DailyEnabled: get("backup_daily_enabled") == "1",
		DailyTime:    get("backup_daily_time"),
		DailyKeep:    atoi("backup_daily_keep", 7),
		LocalDir:     get("backup_local_dir"),
		GitDir:       get("backup_git_dir"),
		GitRemote:    get("backup_git_remote"),
		GitBranch:    get("backup_git_branch"),
		Host:         get("backup_remote_host"),
		Port:         atoi("backup_remote_port", 22),
		User:         get("backup_remote_user"),
		Dir:          get("backup_remote_dir"),
		HostKey:      get("backup_remote_hostkey"),
	}
	if c.Transport == "" {
		c.Transport = "local"
	}
	if c.Port == 0 {
		c.Port = 22
	}
	if c.Schedule == "" {
		c.Schedule = "daily"
	}
	if c.Time == "" {
		c.Time = "03:00"
	}
	if c.DailyTime == "" {
		c.DailyTime = c.Time
	}
	if c.DailyKeep < 1 {
		c.DailyKeep = 7
	}
	if sealed := get("backup_remote_password"); sealed != "" {
		if plain, err := m.box.Open(sealed); err == nil {
			c.Password = plain
			c.HasPassword = true
		}
	}
	c.Encrypt = get("backup_encrypt") == "1"
	if sealed := get("backup_passphrase"); sealed != "" {
		if plain, err := m.box.Open(sealed); err == nil {
			c.Passphrase = plain
			c.HasPassphrase = true
		}
	}
	return c, nil
}

// Save writes the configuration, sealing a new password when one is supplied.
func (m *Manager) Save(c Config) error {
	if msg := c.Validate(); msg != "" {
		return errors.New(msg)
	}
	values := map[string]string{
		"backup_enabled":        map[bool]string{true: "1", false: "0"}[c.Enabled],
		"backup_transport":      c.Transport,
		"backup_schedule":       c.Schedule,
		"backup_time":           c.Time,
		"backup_weekday":        strconv.Itoa(c.Weekday),
		"backup_keep":           strconv.Itoa(c.Keep),
		"backup_daily_enabled":  map[bool]string{true: "1", false: "0"}[c.DailyEnabled],
		"backup_daily_time":     c.DailyTime,
		"backup_daily_keep":     strconv.Itoa(c.DailyKeep),
		"backup_local_dir":      strings.TrimSpace(c.LocalDir),
		"backup_git_dir":        strings.TrimSpace(c.GitDir),
		"backup_git_remote":     strings.TrimSpace(c.GitRemote),
		"backup_git_branch":     strings.TrimSpace(c.GitBranch),
		"backup_remote_host":    strings.TrimSpace(c.Host),
		"backup_remote_port":    strconv.Itoa(c.Port),
		"backup_remote_user":    strings.TrimSpace(c.User),
		"backup_remote_dir":     strings.TrimSpace(c.Dir),
		"backup_remote_hostkey": strings.TrimSpace(c.HostKey),
		"backup_encrypt":        map[bool]string{true: "1", false: "0"}[c.Encrypt],
	}
	if c.Passphrase != "" {
		sealed, err := m.box.Seal(c.Passphrase)
		if err != nil {
			return err
		}
		values["backup_passphrase"] = sealed
	}
	if c.Password != "" {
		sealed, err := m.box.Seal(c.Password)
		if err != nil {
			return err
		}
		values["backup_remote_password"] = sealed
	}
	for k, v := range values {
		if err := m.st.SetSetting(k, v); err != nil {
			return err
		}
	}
	return nil
}

// Status returns the last run.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.status
	if cfg, err := m.Config(); err == nil {
		if next, ok := nextRun(cfg, m.now()); ok {
			out.NextRun = next.UTC().Format(time.RFC3339)
		}
		if next, ok := nextDailyRun(cfg, m.now()); ok {
			out.NextDailyRun = next.UTC().Format(time.RFC3339)
		}
	}
	return out
}

// tier is one of the two schedules: the full copies the primary schedule
// writes, or the daily copies. Each prunes only the files it wrote.
type tier struct {
	prefix string
	daily  bool
}

var (
	fullTier  = tier{prefix: fullPrefix}
	dailyTier = tier{prefix: dailyPrefix, daily: true}
)

func (t tier) keep(cfg Config) int {
	if t.daily {
		return cfg.DailyKeep
	}
	return cfg.Keep
}

// RunNow performs one scheduled backup and records the outcome.
func (m *Manager) RunNow() (Status, error) { return m.manual(fullTier) }

// RunDaily writes one daily copy and prunes the daily files by their own count.
func (m *Manager) RunDaily() (Status, error) { return m.manual(dailyTier) }

func (m *Manager) manual(t tier) (Status, error) {
	if !m.runMu.TryLock() {
		return Status{}, errBusy
	}
	defer m.runMu.Unlock()
	return m.perform(t)
}

// runScheduled waits for a run already in flight and then performs its own, so a
// tier that comes due while another is writing is queued rather than refused.
func (m *Manager) runScheduled(t tier) (Status, error) {
	m.runMu.Lock()
	defer m.runMu.Unlock()
	return m.perform(t)
}

// perform writes one backup. The caller holds runMu.
func (m *Manager) perform(t tier) (Status, error) {
	cfg, err := m.Config()
	if err != nil {
		return m.finish(t, "", err)
	}
	data, err := m.produce()
	if err != nil {
		return m.finish(t, "", err)
	}
	name := t.prefix + m.now().UTC().Format("20060102-150405") + ".json"
	if cfg.Encrypt && cfg.Passphrase != "" {
		if data, err = Encrypt(cfg.Passphrase, data); err != nil {
			return m.finish(t, "", err)
		}
		name += ".enc"
	}
	if err := m.deliver(cfg, t, name, data); err != nil {
		return m.finish(t, "", err)
	}
	return m.finish(t, name, nil)
}

func (m *Manager) finish(t tier, file string, err error) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Each tier reports its own last run, so a daily copy does not show twice:
	// once as the last run and again as the last daily copy.
	if t.daily {
		m.status.LastDailyRun = m.now().UTC().Format(time.RFC3339)
		if file != "" {
			m.status.LastDailyFile = file
		}
	} else {
		m.status.LastRun = m.now().UTC().Format(time.RFC3339)
		m.status.LastFile = file
	}
	if err != nil {
		m.status.LastError = err.Error()
		return m.status, err
	}
	m.status.LastError = ""
	return m.status, nil
}

func (m *Manager) deliver(cfg Config, t tier, name string, data []byte) error {
	keep := t.keep(cfg)
	var target string
	var err error
	switch cfg.Transport {
	case "local":
		target = filepath.Join(cfg.LocalDir, name)
		err = writeLocal(m.log, cfg.LocalDir, t.prefix, name, data, keep)
	case "git":
		target = filepath.Join(cfg.GitDir, name)
		err = writeGit(m.log, cfg, t.prefix, name, data, keep)
	case "sftp":
		target = fmt.Sprintf("sftp://%s@%s:%d%s/%s", cfg.User, cfg.Host, cfg.Port, strings.TrimSuffix(cfg.Dir, "/"), name)
		err = writeSFTP(m.log, cfg, t.prefix, name, data, keep)
	case "ftp":
		target = fmt.Sprintf("ftp://%s@%s:%d%s/%s", cfg.User, cfg.Host, cfg.Port, strings.TrimSuffix(cfg.Dir, "/"), name)
		err = writeFTP(m.log, cfg, t.prefix, name, data, keep)
	default:
		err = fmt.Errorf("unknown backup transport %q", cfg.Transport)
	}
	m.mu.Lock()
	m.status.LastTarget = target
	m.mu.Unlock()
	return err
}

func writeLocal(log *slog.Logger, dir, prefix, name string, data []byte, keep int) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		return err
	}
	pruneWarn(log, dir, prefix, keep)
	return nil
}

func writeGit(log *slog.Logger, cfg Config, prefix, name string, data []byte, keep int) error {
	dir := cfg.GitDir
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		if out, err := git(dir, "init", "-q"); err != nil {
			return fmt.Errorf("git init: %v: %s", err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		return err
	}
	pruneWarn(log, dir, prefix, keep)
	if out, err := git(dir, "add", "-A"); err != nil {
		return fmt.Errorf("git add: %v: %s", err, out)
	}
	if out, err := git(dir, "commit", "-q", "-m", "backup "+name); err != nil {
		return fmt.Errorf("git commit: %v: %s", err, out)
	}
	if cfg.GitRemote != "" {
		branch := cfg.GitBranch
		if branch == "" {
			branch = "main"
		}
		if out, err := git(dir, "push", "--", cfg.GitRemote, "HEAD:"+branch); err != nil {
			return fmt.Errorf("git push: %v: %s", err, out)
		}
	}
	return nil
}

func git(dir string, args ...string) (string, error) {
	args = append([]string{"-c", "safe.directory=" + dir, "-C", dir}, args...)
	out, err := exec.Command("git", args...).CombinedOutput()
	return string(out), err
}

func writeSFTP(log *slog.Logger, cfg Config, prefix, name string, data []byte, keep int) error {
	hostKey, err := parseFingerprint(cfg.HostKey)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            []ssh.AuthMethod{ssh.Password(cfg.Password)},
		HostKeyCallback: hostKey,
		Timeout:         15 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("ssh: %w", err)
	}
	defer client.Close()
	fc, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("sftp: %w", err)
	}
	defer fc.Close()
	remote := path.Join(cfg.Dir, name)
	if cfg.Dir != "" {
		_ = fc.MkdirAll(cfg.Dir)
	}
	f, err := fc.Create(remote)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	pruneRemote(log, "sftp", sftpDir{fc: fc, dir: cfg.Dir}, prefix, keep)
	return nil
}

// remoteDir is the directory a remote transport uploads into.
type remoteDir interface {
	names() ([]string, error)
	remove(name string) error
}

type sftpDir struct {
	fc  *sftp.Client
	dir string
}

func (d sftpDir) names() ([]string, error) {
	entries, err := d.fc.ReadDir(path.Join(d.dir, "."))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

func (d sftpDir) remove(name string) error { return d.fc.Remove(path.Join(d.dir, name)) }

type ftpDir struct{ conn *ftp.ServerConn }

func (d ftpDir) names() ([]string, error) {
	names, err := d.conn.NameList(".")
	if err != nil {
		return nil, err
	}
	// Some servers answer with paths rather than bare names.
	for i, name := range names {
		names[i] = path.Base(name)
	}
	return names, nil
}

func (d ftpDir) remove(name string) error { return d.conn.Delete(name) }

// pruneRemote keeps the newest keep files of this tier. It returns nothing on
// purpose: the copy is already uploaded, so a directory listing or delete that
// fails is a warning and the run stays successful.
func pruneRemote(log *slog.Logger, transport string, dir remoteDir, prefix string, keep int) {
	names, err := dir.names()
	if err != nil {
		log.Warn("backup prune failed; the copy was written", "transport", transport, "err", err)
		return
	}
	var ours []string
	for _, name := range names {
		if isBackupName(name, prefix) {
			ours = append(ours, name)
		}
	}
	for _, name := range oldest(ours, keep) {
		if err := dir.remove(name); err != nil {
			log.Warn("backup prune failed; the copy was written", "transport", transport, "name", name, "err", err)
			return
		}
	}
}

// parseFingerprint checks the SSH host key. A missing fingerprint is refused
// rather than accepted blindly: the backup carries the whole configuration.
func parseFingerprint(raw string) (ssh.HostKeyCallback, error) {
	want := strings.TrimSpace(raw)
	if want == "" {
		return nil, errors.New("an SSH host key fingerprint is required")
	}
	want = strings.TrimPrefix(want, "SHA256:")
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		got := strings.TrimPrefix(ssh.FingerprintSHA256(key), "SHA256:")
		if got != want {
			return fmt.Errorf("ssh host key mismatch: got SHA256:%s", got)
		}
		return nil
	}, nil
}

func writeFTP(log *slog.Logger, cfg Config, prefix, name string, data []byte, keep int) error {
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	conn, err := ftp.Dial(addr, ftp.DialWithTimeout(15*time.Second))
	if err != nil {
		return fmt.Errorf("ftp: %w", err)
	}
	defer conn.Quit()
	if err := conn.Login(cfg.User, cfg.Password); err != nil {
		return fmt.Errorf("ftp login: %w", err)
	}
	if cfg.Dir != "" {
		_ = conn.MakeDir(cfg.Dir)
		if err := conn.ChangeDir(cfg.Dir); err != nil {
			return fmt.Errorf("ftp change dir: %w", err)
		}
	}
	if err := conn.Stor(name, bytes.NewReader(data)); err != nil {
		return err
	}
	pruneRemote(log, "ftp", ftpDir{conn: conn}, prefix, keep)
	return nil
}

// removeFile is os.Remove, replaced in tests to exercise a prune that fails
// after the copy was written.
var removeFile = os.Remove

func pruneWarn(log *slog.Logger, dir, prefix string, keep int) {
	if err := prune(dir, prefix, keep); err != nil {
		log.Warn("backup prune failed; the copy was written", "dir", dir, "err", err)
	}
}

// prune keeps the newest keep files this tier wrote.
func prune(dir, prefix string, keep int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && isBackupName(e.Name(), prefix) {
			names = append(names, e.Name())
		}
	}
	for _, name := range oldest(names, keep) {
		if err := removeFile(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

// isBackupName reports whether name is one of this package's files for a tier.
func isBackupName(name, prefix string) bool {
	return strings.HasPrefix(name, prefix) &&
		(strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".json.enc"))
}

// oldest returns the names to delete so that keep remain. File names begin with
// a sortable timestamp, so plain string order is chronological.
func oldest(names []string, keep int) []string {
	if len(names) <= keep {
		return nil
	}
	sort.Strings(names)
	return names[:len(names)-keep]
}

// nextRun computes the next scheduled time, if the schedule is enabled.
func nextRun(c Config, now time.Time) (time.Time, bool) {
	if !c.Enabled {
		return time.Time{}, false
	}
	hhmm, err := time.Parse("15:04", c.Time)
	if err != nil {
		return time.Time{}, false
	}
	next := time.Date(now.Year(), now.Month(), now.Day(), hhmm.Hour(), hhmm.Minute(), 0, 0, now.Location())
	if c.Schedule == "weekly" {
		for next.Weekday() != time.Weekday(c.Weekday) {
			next = next.AddDate(0, 0, 1)
		}
	}
	if !next.After(now) {
		if c.Schedule == "weekly" {
			next = next.AddDate(0, 0, 7)
		} else {
			next = next.AddDate(0, 0, 1)
		}
	}
	return next, true
}

// nextDailyRun is the daily tier's next time. Config fills DailyTime from the
// primary time when it was never set, so they can share a minute.
func nextDailyRun(c Config, now time.Time) (time.Time, bool) {
	if !c.Enabled || !c.DailyEnabled {
		return time.Time{}, false
	}
	hhmm, err := time.Parse("15:04", c.DailyTime)
	if err != nil {
		return time.Time{}, false
	}
	next := time.Date(now.Year(), now.Month(), now.Day(), hhmm.Hour(), hhmm.Minute(), 0, 0, now.Location())
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next, true
}

// runDue performs the tiers marked due, queueing one behind the other when both
// fell due in the same minute, and reports the files it wrote. An empty result
// means that tier did not run, so the caller keeps its slot pending and retries.
func (m *Manager) runDue(fullDue, dailyDue bool) (full, daily string) {
	if fullDue {
		if status, err := m.runScheduled(fullTier); err != nil {
			m.log.Warn("scheduled backup failed", "err", err)
		} else {
			full = status.LastFile
			m.log.Info("scheduled backup written", "file", full)
		}
	}
	if dailyDue {
		if status, err := m.runScheduled(dailyTier); err != nil {
			m.log.Warn("scheduled daily backup failed", "err", err)
		} else {
			daily = status.LastDailyFile
			m.log.Info("scheduled daily backup written", "file", daily)
		}
	}
	return full, daily
}

// retryFor bounds how long a failed tier stays pending before the schedule
// waits for its next turn instead.
const retryFor = 15 * time.Minute

func clearSlot(log *slog.Logger, slot time.Time, file string, now time.Time) time.Time {
	if slot.IsZero() || file != "" {
		return time.Time{}
	}
	if now.Sub(slot) < retryFor {
		return slot
	}
	log.Warn("scheduled backup gave up retrying", "due", slot.UTC().Format(time.RFC3339))
	return time.Time{}
}

// Start runs both schedules until the context is cancelled. The tiers are
// independent: on the weekly day the weekly and the daily file are both written,
// even when their times fall in the same minute.
func (m *Manager) Start(ctx context.Context) {
	tick := m.ticks
	if tick == nil {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		tick = ticker.C
	}
	// A tier due now stays pending until its file is written, so a slot is never
	// spent by a run that failed, and one queued behind the other still runs.
	var pendingFull, pendingDaily time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			cfg, err := m.Config()
			if err != nil || !cfg.Enabled {
				pendingFull, pendingDaily = time.Time{}, time.Time{}
				continue
			}
			now := m.now()
			if pendingFull.IsZero() {
				if next, ok := nextRun(cfg, now.Add(-time.Minute)); ok && !next.After(now) {
					pendingFull = next
				}
			}
			if pendingDaily.IsZero() {
				if next, ok := nextDailyRun(cfg, now.Add(-time.Minute)); ok && !next.After(now) {
					pendingDaily = next
				}
			}
			if pendingFull.IsZero() && pendingDaily.IsZero() {
				continue
			}
			full, daily := m.runDue(!pendingFull.IsZero(), !pendingDaily.IsZero())
			// A slot is only spent by a file that was written, so a failed run
			// stays pending and the next tick retries it. Give up after a while
			// so a destination that stays down does not retry every minute.
			pendingFull = clearSlot(m.log, pendingFull, full, now)
			pendingDaily = clearSlot(m.log, pendingDaily, daily, now)
		}
	}
}
