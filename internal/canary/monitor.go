package canary

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// Notifier is the slice of the notification manager the monitor needs.
type Notifier interface {
	Enqueue(kind, text, dedupe string, immediate bool)
}

// Snapshot is the last scheduled probe, exposed in the health payload.
type Snapshot struct {
	Enabled       bool   `json:"enabled"`
	Host          string `json:"host"`
	OK            bool   `json:"ok"`
	FailedStage   string `json:"failed_stage,omitempty"`
	Detail        string `json:"detail,omitempty"`
	LatencyMS     int64  `json:"latency_ms"`
	CertExpiresAt string `json:"cert_expires_at,omitempty"`
	CheckedAt     string `json:"checked_at,omitempty"`
	Failures      int    `json:"consecutive_failures"`
	LastNotified  string `json:"last_notified,omitempty"`
}

// Monitor probes one site on an interval, retries a failed probe, and notifies
// once per transition instead of once per attempt.
type Monitor struct {
	st     *store.Store
	probe  Probe
	notify Notifier
	now    func() time.Time

	mu      sync.Mutex
	last    Snapshot
	failing bool
}

// NewMonitor builds a monitor bound to the settings store.
func NewMonitor(st *store.Store, probe Probe, notify Notifier) *Monitor {
	return &Monitor{st: st, probe: probe, notify: notify, now: time.Now}
}

func (m *Monitor) config() (host string, interval time.Duration, retries int, enabled bool) {
	kv, _ := m.st.Settings()
	enabled = kv["canary_enabled"] != "0"
	host = kv["canary_host"]
	interval = 300 * time.Second
	if n, err := strconv.Atoi(kv["canary_interval_s"]); err == nil && n >= 30 && n <= 86400 {
		interval = time.Duration(n) * time.Second
	}
	retries = 2
	if n, err := strconv.Atoi(kv["canary_retries"]); err == nil && n >= 0 && n <= 10 {
		retries = n
	}
	if host == "" {
		if list, _ := m.st.ListProxies(); len(list) > 0 {
			host = list[0].Hostname
		}
	}
	return host, interval, retries, enabled
}

// Check runs one probe with its retries and records the result. It reports
// whether the site failed after every attempt.
func (m *Monitor) Check(ctx context.Context) Snapshot {
	host, _, retries, enabled := m.config()
	snap := Snapshot{Enabled: enabled, Host: host, CheckedAt: m.now().UTC().Format(time.RFC3339)}
	if !enabled || host == "" {
		m.mu.Lock()
		m.last = snap
		m.mu.Unlock()
		return snap
	}
	var res Result
	attempts := retries + 1
	for i := 0; i < attempts; i++ {
		res = m.probe.Run(ctx, host)
		if res.OK {
			break
		}
	}
	snap.OK = res.OK
	snap.FailedStage = res.Failed
	snap.Detail = failureDetail(res)
	snap.CertExpiresAt = res.CertExpiresAt
	for _, st := range res.Stages {
		if st.Name == "connect" && st.OK {
			if d, err := time.ParseDuration(st.Detail); err == nil {
				snap.LatencyMS = d.Milliseconds()
			}
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if res.OK {
		snap.Failures = 0
		if m.failing {
			m.failing = false
			m.notify.Enqueue("uptime", "Canary recovered: "+host+" answers through the proxy again", "canary:"+host+":recovered", true)
		}
	} else {
		snap.Failures = m.last.Failures + 1
		if !m.failing {
			m.failing = true
			snap.LastNotified = "failure"
			m.notify.Enqueue("uptime", "Canary failed at "+res.Failed+" for "+host+" after "+strconv.Itoa(attempts)+" attempts: "+snap.Detail, "canary:"+host, true)
		}
	}
	m.last = snap
	return snap
}

func failureDetail(res Result) string {
	for _, st := range res.Stages {
		if !st.OK {
			if st.Detail != "" {
				return st.Name + ": " + st.Detail
			}
			return st.Name
		}
	}
	return ""
}

// Snapshot returns the last result without running a probe.
func (m *Monitor) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.last
}

// Start probes immediately and then on the configured interval.
func (m *Monitor) Start(ctx context.Context) {
	go func() {
		for {
			_, interval, _, enabled := m.config()
			if enabled {
				m.Check(ctx)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
			}
		}
	}()
}
