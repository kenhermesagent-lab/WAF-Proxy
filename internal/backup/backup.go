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
	Keep      int    `json:"keep"`

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
}

// Status is the last run, reported to the console.
type Status struct {
	LastRun    string `json:"last_run,omitempty"`
	LastError  string `json:"last_error,omitempty"`
	LastFile   string `json:"last_file,omitempty"`
	LastTarget string `json:"last_target,omitempty"`
	NextRun    string `json:"next_run,omitempty"`
}

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
	return ""
}

// Manager schedules and performs backups.
type Manager struct {
	st      *store.Store
	box     *crypto.Box
	log     *slog.Logger
	produce func() ([]byte, error)
	now     func() time.Time

	mu      sync.Mutex
	status  Status
	running bool
}

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
		LocalDir:  get("backup_local_dir"),
		GitDir:    get("backup_git_dir"),
		GitRemote: get("backup_git_remote"),
		GitBranch: get("backup_git_branch"),
		Host:      get("backup_remote_host"),
		Port:      atoi("backup_remote_port", 22),
		User:      get("backup_remote_user"),
		Dir:       get("backup_remote_dir"),
		HostKey:   get("backup_remote_hostkey"),
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
	if sealed := get("backup_remote_password"); sealed != "" {
		if plain, err := m.box.Open(sealed); err == nil {
			c.Password = plain
			c.HasPassword = true
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
		"backup_local_dir":      strings.TrimSpace(c.LocalDir),
		"backup_git_dir":        strings.TrimSpace(c.GitDir),
		"backup_git_remote":     strings.TrimSpace(c.GitRemote),
		"backup_git_branch":     strings.TrimSpace(c.GitBranch),
		"backup_remote_host":    strings.TrimSpace(c.Host),
		"backup_remote_port":    strconv.Itoa(c.Port),
		"backup_remote_user":    strings.TrimSpace(c.User),
		"backup_remote_dir":     strings.TrimSpace(c.Dir),
		"backup_remote_hostkey": strings.TrimSpace(c.HostKey),
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
	}
	return out
}

// RunNow performs one backup and records the outcome.
func (m *Manager) RunNow() (Status, error) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return Status{}, errors.New("a backup is already running")
	}
	m.running = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()

	cfg, err := m.Config()
	if err != nil {
		return m.finish("", err)
	}
	data, err := m.produce()
	if err != nil {
		return m.finish("", err)
	}
	name := "wafproxy-backup-" + m.now().UTC().Format("20060102-150405") + ".json"
	if err := m.deliver(cfg, name, data); err != nil {
		return m.finish("", err)
	}
	return m.finish(name, nil)
}

func (m *Manager) finish(file string, err error) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status.LastRun = m.now().UTC().Format(time.RFC3339)
	m.status.LastFile = file
	if err != nil {
		m.status.LastError = err.Error()
		return m.status, err
	}
	m.status.LastError = ""
	return m.status, nil
}

func (m *Manager) deliver(cfg Config, name string, data []byte) error {
	var target string
	var err error
	switch cfg.Transport {
	case "local":
		target = filepath.Join(cfg.LocalDir, name)
		err = writeLocal(cfg.LocalDir, name, data, cfg.Keep)
	case "git":
		target = filepath.Join(cfg.GitDir, name)
		err = writeGit(cfg, name, data)
	case "sftp":
		target = fmt.Sprintf("sftp://%s@%s:%d%s/%s", cfg.User, cfg.Host, cfg.Port, strings.TrimSuffix(cfg.Dir, "/"), name)
		err = writeSFTP(cfg, name, data)
	case "ftp":
		target = fmt.Sprintf("ftp://%s@%s:%d%s/%s", cfg.User, cfg.Host, cfg.Port, strings.TrimSuffix(cfg.Dir, "/"), name)
		err = writeFTP(cfg, name, data)
	default:
		err = fmt.Errorf("unknown backup transport %q", cfg.Transport)
	}
	m.mu.Lock()
	m.status.LastTarget = target
	m.mu.Unlock()
	return err
}

func writeLocal(dir, name string, data []byte, keep int) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		return err
	}
	return prune(dir, keep)
}

func writeGit(cfg Config, name string, data []byte) error {
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
	if err := prune(dir, cfg.Keep); err != nil {
		return err
	}
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

func writeSFTP(cfg Config, name string, data []byte) error {
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
	return f.Close()
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

func writeFTP(cfg Config, name string, data []byte) error {
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
	return conn.Stor(name, bytes.NewReader(data))
}

// prune keeps the newest keep files this package wrote.
func prune(dir string, keep int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "wafproxy-backup-") && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	if len(names) <= keep {
		return nil
	}
	sort.Strings(names)
	for _, name := range names[:len(names)-keep] {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
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

// Start runs the schedule until the context is cancelled.
func (m *Manager) Start(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	var lastRun string
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cfg, err := m.Config()
			if err != nil || !cfg.Enabled {
				continue
			}
			now := m.now()
			next, ok := nextRun(cfg, now.Add(-time.Minute))
			if !ok || next.After(now) {
				continue
			}
			key := next.Format(time.RFC3339)
			if key == lastRun {
				continue
			}
			lastRun = key
			if _, err := m.RunNow(); err != nil {
				m.log.Warn("scheduled backup failed", "err", err)
				continue
			}
			m.log.Info("scheduled backup written", "file", m.Status().LastFile)
		}
	}
}
