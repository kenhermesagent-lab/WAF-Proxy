// Package anomaly turns the per-proxy counters into detections: an outbound
// byte spike, a request-rate spike, or a burst of failed gate logins.
package anomaly

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// Window is the detection period: one minute of counters, compared with the
// same proxy's recent windows.
const Window = time.Minute

// Notifier is the slice of notify.Manager the detector needs.
type Notifier interface {
	Enqueue(kind, text, dedupe string, immediate bool)
}

// Config holds the thresholds, all editable in the console.
type Config struct {
	Enabled      bool    `json:"enabled"`
	EgressMB     int     `json:"egress_mb"`
	EgressFactor float64 `json:"egress_factor"`
	RPS          int     `json:"rate_rps"`
	RateFactor   float64 `json:"rate_factor"`
	AuthBurst    int     `json:"auth_burst"`
}

// Defaults are the values in the design doc.
func Defaults() Config {
	return Config{Enabled: true, EgressMB: 5, EgressFactor: 4, RPS: 200, RateFactor: 3, AuthBurst: 20}
}

// Validate rejects a threshold the detector cannot work with.
func (c Config) Validate() string {
	switch {
	case c.EgressMB < 1 || c.EgressMB > 102400:
		return "the egress floor must be 1-102400 MB"
	case c.EgressFactor < 1.1 || c.EgressFactor > 100:
		return "the egress factor must be between 1.1 and 100"
	case c.RPS < 1 || c.RPS > 100000:
		return "the request-rate threshold must be 1-100000 rps"
	case c.RateFactor < 1.1 || c.RateFactor > 1000:
		return "the rate factor must be between 1.1 and 1000"
	case c.AuthBurst < 1 || c.AuthBurst > 10000:
		return "the login-failure burst must be 1-10000"
	}
	return ""
}

type sample struct {
	requests int64
	bytesOut int64
	set      bool
}

// Manager evaluates one window per minute.
type Manager struct {
	st     *store.Store
	met    *metrics.Collector
	notify Notifier
	log    *slog.Logger
	now    func() time.Time

	mu     sync.Mutex
	prev   map[int64]sample
	egress map[int64][]float64
	rates  map[int64][]float64
}

// New returns a detector bound to the store and the metrics collector.
func New(st *store.Store, met *metrics.Collector, notify Notifier, log *slog.Logger) *Manager {
	return &Manager{
		st: st, met: met, notify: notify, log: log, now: time.Now,
		prev:   map[int64]sample{},
		egress: map[int64][]float64{},
		rates:  map[int64][]float64{},
	}
}

// Config reads the thresholds, filling in defaults for keys that were never set.
func (m *Manager) Config() (Config, error) {
	kv, err := m.st.Settings()
	if err != nil {
		return Config{}, err
	}
	c := Defaults()
	if raw, ok := kv["anomaly_enabled"]; ok {
		c.Enabled = raw == "1"
	}
	atoi := func(key string, dst *int) {
		if n, err := strconv.Atoi(kv[key]); err == nil {
			*dst = n
		}
	}
	atof := func(key string, dst *float64) {
		if f, err := strconv.ParseFloat(kv[key], 64); err == nil {
			*dst = f
		}
	}
	atoi("anomaly_egress_mb", &c.EgressMB)
	atoi("anomaly_rate_rps", &c.RPS)
	atoi("anomaly_auth_burst", &c.AuthBurst)
	atof("anomaly_egress_factor", &c.EgressFactor)
	atof("anomaly_rate_factor", &c.RateFactor)
	return c, nil
}

// Save writes the thresholds after validation.
func (m *Manager) Save(c Config) error {
	if msg := c.Validate(); msg != "" {
		return errors.New(msg)
	}
	values := map[string]string{
		"anomaly_enabled":       map[bool]string{true: "1", false: "0"}[c.Enabled],
		"anomaly_egress_mb":     strconv.Itoa(c.EgressMB),
		"anomaly_egress_factor": strconv.FormatFloat(c.EgressFactor, 'f', -1, 64),
		"anomaly_rate_rps":      strconv.Itoa(c.RPS),
		"anomaly_rate_factor":   strconv.FormatFloat(c.RateFactor, 'f', -1, 64),
		"anomaly_auth_burst":    strconv.Itoa(c.AuthBurst),
	}
	for k, v := range values {
		if err := m.st.SetSetting(k, v); err != nil {
			return err
		}
	}
	return nil
}

// Start evaluates a window every minute until the context is cancelled.
func (m *Manager) Start(ctx context.Context) {
	ticker := time.NewTicker(Window)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := m.Tick(now); err != nil {
				m.log.Warn("anomaly detection failed", "err", err)
			}
		}
	}
}

// Tick compares the counters with the previous sample and records any detection.
func (m *Manager) Tick(now time.Time) error {
	cfg, err := m.Config()
	if err != nil {
		return err
	}
	if !cfg.Enabled {
		return nil
	}
	snap := m.met.Snapshot()
	failures, err := m.st.GateFailuresSince(now.Add(-Window))
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for key, c := range snap.Proxies {
		id, err := strconv.ParseInt(key, 10, 64)
		if err != nil || id == 0 {
			continue
		}
		prev := m.prev[id]
		m.prev[id] = sample{requests: c.Requests, bytesOut: c.BytesOut, set: true}
		if !prev.set {
			continue
		}
		// Counters only grow; a decrease means the process restarted.
		out := c.BytesOut - prev.bytesOut
		reqs := c.Requests - prev.requests
		if out < 0 {
			out = 0
		}
		if reqs < 0 {
			reqs = 0
		}
		egressBase, egressHist := median(m.egress[id])
		rateBase, rateHist := median(m.rates[id])
		m.egress[id] = append(egressHist, float64(out))
		m.rates[id] = append(rateHist, float64(reqs)/Window.Seconds())

		floor := float64(cfg.EgressMB) * (1 << 20)
		if float64(out) >= floor && float64(out) >= cfg.EgressFactor*egressBase {
			m.raise(cfg, model.AnomalyEvent{
				Kind: "egress_spike", ProxyID: id, WindowStart: now.Add(-Window), WindowSeconds: int(Window.Seconds()),
				Value: float64(out), Baseline: egressBase,
				Detail: fmt.Sprintf("%s out in one minute", humanBytes(float64(out))),
			})
		}
		rps := float64(reqs) / Window.Seconds()
		if rps >= float64(cfg.RPS) && rps >= cfg.RateFactor*rateBase {
			m.raise(cfg, model.AnomalyEvent{
				Kind: "rate_spike", ProxyID: id, WindowStart: now.Add(-Window), WindowSeconds: int(Window.Seconds()),
				Value: rps, Baseline: rateBase,
				Detail: fmt.Sprintf("%.0f requests/s", rps),
			})
		}
	}

	for id, n := range failures {
		if n < cfg.AuthBurst {
			continue
		}
		m.raise(cfg, model.AnomalyEvent{
			Kind: "auth_burst", ProxyID: id, WindowStart: now.Add(-Window), WindowSeconds: int(Window.Seconds()),
			Value: float64(n), Baseline: 0,
			Detail: fmt.Sprintf("%d failed logins in one minute", n),
		})
	}
	return nil
}

// raise stores a detection unless the same condition is already open, in which
// case it only refreshes that event so a long spike stays one row.
func (m *Manager) raise(cfg Config, e model.AnomalyEvent) {
	since := m.now().Add(-10 * time.Minute)
	if open, ok, err := m.st.OpenAnomalyEvent(e.Kind, e.ProxyID, since); err != nil {
		m.log.Warn("anomaly lookup failed", "err", err)
	} else if ok {
		if err := m.st.TouchAnomalyEvent(open.ID, e.Value); err != nil {
			m.log.Warn("anomaly refresh failed", "err", err)
		}
		return
	}
	if e.ProxyID != 0 {
		if p, err := m.st.GetProxy(e.ProxyID); err == nil {
			e.ProxyHost = p.Hostname
		}
	}
	if _, err := m.st.CreateAnomalyEvent(&e); err != nil {
		m.log.Warn("anomaly store failed", "err", err)
		return
	}
	m.notify.Enqueue(e.Kind, describe(e), "anomaly:"+e.Kind+":"+strconv.FormatInt(e.ProxyID, 10), true)
}

func describe(e model.AnomalyEvent) string {
	host := e.ProxyHost
	if host == "" {
		host = "proxy " + strconv.FormatInt(e.ProxyID, 10)
	}
	switch e.Kind {
	case "egress_spike":
		return fmt.Sprintf("Outbound traffic spike: %s — %s (baseline %s)", host, e.Detail, humanBytes(e.Baseline))
	case "rate_spike":
		return fmt.Sprintf("Request-rate spike: %s — %s (baseline %.0f rps)", host, e.Detail, e.Baseline)
	case "auth_burst":
		return fmt.Sprintf("Authentication failure burst: %s — %s", host, e.Detail)
	}
	return fmt.Sprintf("%s: %s — %s", e.Kind, host, e.Detail)
}

func humanBytes(v float64) string {
	switch {
	case v >= 1<<30:
		return fmt.Sprintf("%.1f GB", v/(1<<30))
	case v >= 1<<20:
		return fmt.Sprintf("%.1f MB", v/(1<<20))
	case v >= 1<<10:
		return fmt.Sprintf("%.1f KB", v/(1<<10))
	}
	return fmt.Sprintf("%.0f B", v)
}

// median returns the middle of the history (zero when it is empty) and the
// history with this window appended, capped at an hour.
func median(hist []float64) (float64, []float64) {
	base := 0.0
	if len(hist) > 0 {
		sorted := append([]float64(nil), hist...)
		sort.Float64s(sorted)
		base = sorted[len(sorted)/2]
	}
	if len(hist) >= 60 {
		hist = hist[1:]
	}
	return base, hist
}
