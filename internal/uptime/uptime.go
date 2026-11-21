// Package uptime probes every enabled proxy upstream and reports availability.
package uptime

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

const (
	// StateUnknown means the target has not been probed yet, or has no upstream.
	StateUnknown = "unknown"
	StateUp      = "up"
	StateDown    = "down"

	historyWindow = 24 * time.Hour
)

// Notifier is the subset of the notification manager used for state changes.
type Notifier interface {
	Enqueue(kind, text, dedupe string, immediate bool)
}

// Target is one probed backend plus its recent availability.
type Target struct {
	ID         string    `json:"id"`
	ProxyID    int64     `json:"proxy_id"`
	ProxyHost  string    `json:"proxy_host"`
	URL        string    `json:"url"`
	State      string    `json:"state"`
	StatusCode int       `json:"status_code"`
	LatencyMS  int64     `json:"latency_ms"`
	LastCheck  time.Time `json:"last_check"`
	LastChange time.Time `json:"last_change"`
	Error      string    `json:"error"`
	Uptime24   float64   `json:"uptime_24"`
	Checks24   int       `json:"checks_24"`
}

// ProxyStatus combines a proxy's upstream checks.
type ProxyStatus struct {
	ProxyID int64  `json:"proxy_id"`
	Host    string `json:"host"`
	State   string `json:"state"`
	Targets int    `json:"targets"`
	Up      int    `json:"up"`
}

// Snapshot is served to the admin UI.
type Snapshot struct {
	ProcessUptimeS int64         `json:"process_uptime_s"`
	Targets        []Target      `json:"targets"`
	Proxies        []ProxyStatus `json:"proxies"`
	CheckedAt      time.Time     `json:"checked_at"`
}

type targetState struct {
	Target
	history []bool
}

// Manager probes all configured upstreams on an interval.
type Manager struct {
	st       *store.Store
	notifier Notifier
	log      *slog.Logger
	client   *http.Client
	interval time.Duration
	started  time.Time

	mu       sync.Mutex
	targets  map[string]*targetState
	proxies  []ProxyStatus
	lastScan time.Time
}

// New creates a monitor. A nil notifier disables alerts but keeps the status.
func New(st *store.Store, notifier Notifier, log *slog.Logger) *Manager {
	return &Manager{
		st: st, notifier: notifier, log: log,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				Proxy:             nil,
				DisableKeepAlives: true,
			},
		},
		interval: 30 * time.Second,
		started:  time.Now(),
		targets:  map[string]*targetState{},
		proxies:  []ProxyStatus{},
	}
}

// Start runs a check immediately and then every interval until cancellation.
func (m *Manager) Start(ctx context.Context) {
	m.Check(ctx)
	go func() {
		t := time.NewTicker(m.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.Check(ctx)
			}
		}
	}()
}

// Check probes every enabled proxy upstream once.
func (m *Manager) Check(ctx context.Context) Snapshot {
	list, err := m.st.ListProxies()
	if err != nil {
		m.log.Warn("uptime: list proxies", "err", err)
		return m.Snapshot()
	}

	type probe struct {
		id    string
		proxy model.Proxy
		url   string
	}
	probes := []probe{}
	keep := map[string]bool{}
	for _, p := range list {
		ups, err := m.st.ListUpstreams(p.ID)
		if err != nil {
			continue
		}
		enabled := 0
		for _, u := range ups {
			if !u.Enabled {
				continue
			}
			enabled++
			if !p.Enabled {
				continue
			}
			id := fmt.Sprintf("upstream:%d", u.ID)
			keep[id] = true
			probes = append(probes, probe{id: id, proxy: p, url: u.URL})
		}
		if p.Enabled && enabled == 0 {
			id := fmt.Sprintf("proxy:%d", p.ID)
			keep[id] = true
			probes = append(probes, probe{id: id, proxy: p})
		}
	}

	results := make(chan Target, len(probes))
	var wg sync.WaitGroup
	for _, p := range probes {
		wg.Add(1)
		go func(p probe) {
			defer wg.Done()
			results <- m.probe(ctx, p.id, p.proxy, p.url)
		}(p)
	}
	wg.Wait()
	close(results)

	now := time.Now()
	m.mu.Lock()
	for id := range m.targets {
		if !keep[id] {
			delete(m.targets, id)
		}
	}
	for result := range results {
		prev := m.targets[result.ID]
		if prev == nil {
			prev = &targetState{Target: result}
			prev.LastChange = now
			if result.State == StateDown {
				m.alertDown(prev)
			}
		} else {
			was := prev.State
			lastChange := prev.LastChange
			prev.Target = result
			prev.LastChange = lastChange
			if result.State != was {
				prev.LastChange = now
				if result.State == StateDown {
					m.alertDown(prev)
				} else if result.State == StateUp && was == StateDown {
					m.alertUp(prev)
				}
			}
			if result.State != StateUnknown {
				prev.history = append(prev.history, result.State == StateUp)
				prev.history = trimHistory(prev.history)
			}
		}
		if prev.history == nil && result.State != StateUnknown {
			prev.history = []bool{result.State == StateUp}
		}
		prev.Uptime24, prev.Checks24 = uptime(prev.history)
		m.targets[result.ID] = prev
	}
	m.rebuildProxiesLocked(list)
	m.lastScan = now
	m.mu.Unlock()
	return m.Snapshot()
}

func (m *Manager) probe(ctx context.Context, id string, p model.Proxy, raw string) Target {
	out := Target{ID: id, ProxyID: p.ID, ProxyHost: p.Hostname, URL: raw,
		State: StateUnknown, LastCheck: time.Now()}
	if raw == "" {
		out.Error = "no enabled upstream"
		return out
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		out.State = StateDown
		out.Error = "upstream is not an http(s) URL"
		return out
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
	if err != nil {
		out.State = StateDown
		out.Error = err.Error()
		return out
	}
	req.Header.Set("User-Agent", "WAF-Proxy uptime/1.0")
	started := time.Now()
	resp, err := m.client.Do(req)
	out.LatencyMS = time.Since(started).Milliseconds()
	if err != nil {
		out.State = StateDown
		out.Error = err.Error()
		return out
	}
	defer resp.Body.Close()
	out.StatusCode = resp.StatusCode
	if resp.StatusCode >= 500 {
		out.State = StateDown
		out.Error = fmt.Sprintf("backend returned %d", resp.StatusCode)
		return out
	}
	out.State = StateUp
	return out
}

func trimHistory(h []bool) []bool {
	max := int(historyWindow / (30 * time.Second))
	if len(h) > max {
		h = h[len(h)-max:]
	}
	return h
}

func uptime(h []bool) (float64, int) {
	if len(h) == 0 {
		return 0, 0
	}
	up := 0
	for _, ok := range h {
		if ok {
			up++
		}
	}
	return float64(up) / float64(len(h)) * 100, len(h)
}

func (m *Manager) rebuildProxiesLocked(list []model.Proxy) {
	byProxy := map[int64][]*targetState{}
	for _, t := range m.targets {
		byProxy[t.ProxyID] = append(byProxy[t.ProxyID], t)
	}
	out := make([]ProxyStatus, 0, len(list))
	for _, p := range list {
		ps := ProxyStatus{ProxyID: p.ID, Host: p.Hostname, State: StateUnknown}
		targets := byProxy[p.ID]
		ps.Targets = len(targets)
		for _, t := range targets {
			if t.State == StateUp {
				ps.Up++
			}
			if t.State == StateDown {
				ps.State = StateDown
			} else if ps.State != StateDown && t.State == StateUp {
				ps.State = StateUp
			}
		}
		if !p.Enabled {
			ps.State = "disabled"
		}
		out = append(out, ps)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	m.proxies = out
}

// Snapshot returns a copy safe for JSON encoding.
func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := Snapshot{ProcessUptimeS: int64(time.Since(m.started).Seconds()),
		Targets: []Target{}, Proxies: append([]ProxyStatus{}, m.proxies...), CheckedAt: m.lastScan}
	for _, t := range m.targets {
		out.Targets = append(out.Targets, t.Target)
	}
	sort.Slice(out.Targets, func(i, j int) bool {
		if out.Targets[i].ProxyHost == out.Targets[j].ProxyHost {
			return out.Targets[i].URL < out.Targets[j].URL
		}
		return out.Targets[i].ProxyHost < out.Targets[j].ProxyHost
	})
	return out
}

func (m *Manager) alertDown(t *targetState) {
	if m.notifier == nil {
		return
	}
	detail := t.URL
	if detail == "" {
		detail = "no enabled upstream"
	}
	text := fmt.Sprintf("Backend down: %s → %s (%s)", t.ProxyHost, detail, strings.TrimSpace(t.Error))
	m.notifier.Enqueue("uptime", text, "uptime:"+t.ID+":down", true)
}

func (m *Manager) alertUp(t *targetState) {
	if m.notifier == nil {
		return
	}
	text := fmt.Sprintf("Backend recovered: %s → %s (%d ms)", t.ProxyHost, t.URL, t.LatencyMS)
	m.notifier.Enqueue("uptime", text, "uptime:"+t.ID+":up", true)
}
