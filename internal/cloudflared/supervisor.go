package cloudflared

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultMetricsAddr is where cloudflared exposes its readiness and metrics
// endpoints. The console probes them to tell "the process started" from
// "registered with the Cloudflare edge".
const DefaultMetricsAddr = "127.0.0.1:20241"

// ErrNotInstalled means the cloudflared binary is missing.
var ErrNotInstalled = errors.New("cloudflared is not installed on this host")

// State is the connector's lifecycle as the page displays it.
type State string

const (
	StateStopped  State = "stopped"
	StateStarting State = "starting"
	StateRunning  State = "running"
	StateError    State = "error"
)

// Snapshot is the state the API returns.
type Snapshot struct {
	Installed       bool     `json:"installed"`
	Version         string   `json:"version"`
	State           State    `json:"state"`
	Connections     int      `json:"connections"`
	Error           string   `json:"error,omitempty"`
	Log             []string `json:"log"`
	RestartRequired bool     `json:"restart_required"`
}

// Supervisor owns one cloudflared process.
type Supervisor struct {
	log         *slog.Logger
	metricsAddr string

	mu            sync.Mutex
	bin           string
	version       string
	checkedAt     time.Time
	state         State
	lastErr       string
	connections   int
	startVersion  string
	cmd           *exec.Cmd
	tail          *lineRing
	readyTimeout  time.Duration
	probeEvery    time.Duration
	probe         func(context.Context) error
	metricsLookup func() int
}

// New returns a supervisor bound to the loopback metrics address.
func New(log *slog.Logger) *Supervisor {
	addr := strings.TrimSpace(os.Getenv("WAFPROXY_CLOUDFLARED_METRICS"))
	if addr == "" {
		addr = DefaultMetricsAddr
	}
	s := &Supervisor{
		log:          log,
		metricsAddr:  addr,
		state:        StateStopped,
		connections:  0,
		readyTimeout: 30 * time.Second,
		tail:         newLineRing(40),
		probeEvery:   2 * time.Second,
	}
	s.probe = func(ctx context.Context) error { return getOK(ctx, "http://"+addr+"/ready") }
	s.metricsLookup = func() int { return fetchConnections(addr) }
	return s
}

// MetricsAddr is the loopback address the connector publishes on.
func (s *Supervisor) MetricsAddr() string { return s.metricsAddr }

// RefreshVersion re-reads the binary and its version, at most every 30 s unless
// forced, so a page that polls does not spawn a process on every request.
func (s *Supervisor) RefreshVersion(force bool) {
	s.mu.Lock()
	fresh := !force && s.checkedAt.After(time.Now().Add(-30*time.Second))
	s.mu.Unlock()
	if fresh {
		return
	}
	path, version := detect()
	s.mu.Lock()
	s.bin, s.version, s.checkedAt = path, version, time.Now()
	s.mu.Unlock()
}

// Start runs the connector with the given token. A failure leaves the state in
// error with the reason, so the page can offer a retry.
func (s *Supervisor) Start(token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("a tunnel token is required")
	}
	s.Stop()
	s.RefreshVersion(true)
	s.mu.Lock()
	path, version := s.bin, s.version
	s.mu.Unlock()
	if path == "" {
		s.setError(ErrNotInstalled.Error())
		return ErrNotInstalled
	}
	// The token is an argv entry because that is cloudflared's own interface.
	// The environment is no more private: /proc/<pid>/environ is readable by the
	// same users who can read the argv of a root-owned service.
	cmd := exec.Command(path, "tunnel", "run", "--no-autoupdate",
		"--metrics", s.metricsAddr, "--token", token)
	tail := newLineRing(40)
	cmd.Stdout, cmd.Stderr = tail, tail
	if err := cmd.Start(); err != nil {
		s.setError(err.Error())
		return err
	}
	s.mu.Lock()
	s.cmd, s.state, s.lastErr = cmd, StateStarting, ""
	s.startVersion = version
	s.connections = 0
	s.tail = tail
	s.mu.Unlock()
	s.log.Info("cloudflared connector starting", "version", version, "metrics", s.metricsAddr)
	go s.watch(cmd, tail)
	return nil
}

// Stop ends the process. It is safe when nothing is running.
func (s *Supervisor) Stop() {
	s.mu.Lock()
	cmd := s.cmd
	s.cmd = nil
	s.state = StateStopped
	s.connections = 0
	s.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

// Restart replaces the running connector, picking up a new token.
func (s *Supervisor) Restart(token string) error { return s.Start(token) }

// Snapshot reports the current state without blocking on the child process.
func (s *Supervisor) Snapshot() Snapshot {
	s.RefreshVersion(false)
	s.mu.Lock()
	defer s.mu.Unlock()
	logLines := s.tail.snapshot()
	state := s.state
	connections := s.connections
	if state != StateRunning {
		connections = 0
	}
	restart := s.version != "" && s.startVersion != "" && s.version != s.startVersion && state != StateStopped
	return Snapshot{
		Installed:       s.bin != "",
		Version:         s.version,
		State:           state,
		Connections:     connections,
		Error:           s.lastErr,
		Log:             logLines,
		RestartRequired: restart,
	}
}

// watch waits for readiness, then keeps the connection count fresh. It ends
// when the process exits or Stop replaces it.
func (s *Supervisor) watch(cmd *exec.Cmd, tail *lineRing) {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	ready := false
	deadline := time.Now().Add(s.readyTimeout)
	ticker := time.NewTicker(s.probeEvery)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			s.fail(cmd, err, tail)
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err := s.probe(ctx)
			cancel()
			if !ready {
				switch {
				case err == nil:
					ready = true
					s.mu.Lock()
					if s.cmd == cmd {
						s.state = StateRunning
					}
					s.mu.Unlock()
					s.log.Info("cloudflared connector registered with the edge")
				case time.Now().After(deadline):
					// Keep the process: a slow edge handshake may still finish,
					// and the page can retry. The state stays error.
					s.mu.Lock()
					if s.cmd == cmd && s.state == StateStarting {
						s.state = StateError
						s.lastErr = "the connector did not report ready within " + s.readyTimeout.String()
					}
					s.mu.Unlock()
				}
				continue
			}
			n := s.metricsLookup()
			s.mu.Lock()
			if s.cmd == cmd {
				s.connections = n
			}
			s.mu.Unlock()
		}
	}
}

// fail records an unexpected exit. A Stop() already cleared the command, so a
// deliberate stop is not reported as an error.
func (s *Supervisor) fail(cmd *exec.Cmd, err error, tail *lineRing) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != cmd {
		return
	}
	s.cmd = nil
	s.state = StateError
	s.connections = 0
	if err != nil {
		s.lastErr = err.Error()
	} else {
		s.lastErr = "the connector exited"
	}
	if last := tail.lastLine(); last != "" {
		s.lastErr += ": " + last
	}
	s.log.Error("cloudflared connector exited", "err", s.lastErr)
}

func (s *Supervisor) setError(message string) {
	s.mu.Lock()
	s.state, s.lastErr = StateError, message
	s.mu.Unlock()
}

var versionRE = regexp.MustCompile(`version v?([0-9][^\s]*)`)

// detect finds the binary and asks it for its version.
func detect() (path, version string) {
	path, err := exec.LookPath("cloudflared")
	if err != nil {
		return "", ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil {
		return path, ""
	}
	if m := versionRE.FindStringSubmatch(string(out)); m != nil {
		version = m[1]
	}
	return path, version
}

func getOK(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("readiness endpoint returned " + resp.Status)
	}
	return nil
}

// fetchConnections sums the edge connections cloudflared exports. It returns -1
// when the metric is absent, so "connected, count unknown" is never shown as
// zero.
func fetchConnections(addr string) int {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/metrics")
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	sum, found := 0, false
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cloudflared_tunnel_ha_connections") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if n, err := strconv.ParseFloat(fields[len(fields)-1], 64); err == nil {
			sum += int(n)
			found = true
		}
	}
	if !found {
		return -1
	}
	return sum
}

// lineRing keeps the last lines of connector output for the page.
type lineRing struct {
	mu      sync.Mutex
	entries []string
	max     int
	part    []byte
}

func newLineRing(max int) *lineRing { return &lineRing{max: max} }

func (r *lineRing) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.part = append(r.part, p...)
	for {
		i := bytes.IndexByte(r.part, '\n')
		if i < 0 {
			break
		}
		r.append(string(r.part[:i]))
		r.part = r.part[i+1:]
	}
	if len(r.part) > 4096 {
		r.part = r.part[len(r.part)-4096:]
	}
	return len(p), nil
}

func (r *lineRing) append(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	r.entries = append(r.entries, line)
	if len(r.entries) > r.max {
		r.entries = r.entries[len(r.entries)-r.max:]
	}
}

func (r *lineRing) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.entries))
	copy(out, r.entries)
	return out
}

func (r *lineRing) lastLine() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) == 0 {
		return ""
	}
	return r.entries[len(r.entries)-1]
}
