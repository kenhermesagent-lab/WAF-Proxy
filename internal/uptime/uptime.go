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

// Sample is one probe result, kept for the 24-hour latency history.
type Sample struct {
	At    time.Time `json:"at"`
	MS    int64     `json:"ms"`
	Code  int       `json:"code"`
	OK    bool      `json:"ok"`
	Error string    `json:"error,omitempty"`
}

// Incident is one run of consecutive failed probes.
type Incident struct {
	Start  time.Time  `json:"start"`
	End    *time.Time `json:"end"`
	Checks int        `json:"checks"`
	Error  string     `json:"error"`
}

// SlowSpan is a run of probes that took far longer than the target's usual
// latency, which is what an operator looks for after a report of "it was slow".
type SlowSpan struct {
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
	Checks int       `json:"checks"`
	AvgMS  int64     `json:"avg_ms"`
	MaxMS  int64     `json:"max_ms"`
}

// Stats summarises the successful samples of one target.
type Stats struct {
	Checks int   `json:"checks"`
	Up     int   `json:"up"`
	AvgMS  int64 `json:"avg_ms"`
	P50MS  int64 `json:"p50_ms"`
	P95MS  int64 `json:"p95_ms"`
	P99MS  int64 `json:"p99_ms"`
	MaxMS  int64 `json:"max_ms"`
}

// History is the uptime analytics of one probed target.
type History struct {
	Target
	Samples   []Sample   `json:"samples"`
	Incidents []Incident `json:"incidents"`
	Slow      []SlowSpan `json:"slow"`
	Stats     Stats      `json:"stats"`
}

type targetState struct {
	Target
	history []bool
	samples []Sample
	// incidents holds closed outages; an outage still running is appended when
	// the history is read, so a reader never sees it without an end.
	incidents  []Incident
	downSince  time.Time
	downChecks int
	downError  string
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
		prev.recordSample(now)
		prev.trackIncident(now)
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

// recordSample appends the probe that just ran and drops anything older than
// the 24-hour window, so the ring never grows with uptime.
func (t *targetState) recordSample(now time.Time) {
	if t.State == StateUnknown {
		return
	}
	t.samples = append(t.samples, Sample{At: now, MS: t.LatencyMS, Code: t.StatusCode,
		OK: t.State == StateUp, Error: t.Error})
	cutoff := now.Add(-historyWindow)
	drop := 0
	for drop < len(t.samples) && t.samples[drop].At.Before(cutoff) {
		drop++
	}
	if drop > 0 {
		t.samples = t.samples[drop:]
	}
}

// trackIncident opens an outage on the first failed probe and closes it on the
// next success, so the drawer can say when a backend went down and came back.
func (t *targetState) trackIncident(now time.Time) {
	if t.State == StateDown {
		if t.downSince.IsZero() {
			t.downSince = now
		}
		t.downChecks++
		t.downError = t.Error
		return
	}
	if t.downSince.IsZero() {
		return
	}
	end := now
	t.incidents = append(t.incidents, Incident{Start: t.downSince, End: &end,
		Checks: t.downChecks, Error: t.downError})
	t.downSince, t.downChecks, t.downError = time.Time{}, 0, ""
	cutoff := now.Add(-historyWindow)
	kept := t.incidents[:0]
	for _, inc := range t.incidents {
		if inc.End != nil && inc.End.Before(cutoff) {
			continue
		}
		kept = append(kept, inc)
	}
	t.incidents = kept
}

// History returns the samples, outages and slow spans of every target behind
// one proxy.
func (m *Manager) History(proxyID int64) []History {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []History{}
	for _, t := range m.targets {
		if t.ProxyID != proxyID {
			continue
		}
		h := History{Target: t.Target, Samples: append([]Sample{}, t.samples...),
			Incidents: append([]Incident{}, t.incidents...)}
		if !t.downSince.IsZero() {
			h.Incidents = append(h.Incidents, Incident{Start: t.downSince,
				Checks: t.downChecks, Error: t.downError})
		}
		h.Stats = stats(t.samples)
		h.Slow = slowSpans(t.samples, h.Stats)
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

func stats(samples []Sample) Stats {
	out := Stats{Checks: len(samples)}
	lat := make([]int64, 0, len(samples))
	var sum int64
	for _, s := range samples {
		if !s.OK {
			continue
		}
		out.Up++
		lat = append(lat, s.MS)
		sum += s.MS
	}
	if len(lat) == 0 {
		return out
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	out.AvgMS = sum / int64(len(lat))
	out.P50MS = percentile(lat, 50)
	out.P95MS = percentile(lat, 95)
	out.P99MS = percentile(lat, 99)
	out.MaxMS = lat[len(lat)-1]
	return out
}

func percentile(sorted []int64, p int) int64 {
	if len(sorted) == 0 {
		return 0
	}
	i := (p*len(sorted)+99)/100 - 1
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

// slowSpans groups consecutive successful probes that took at least 250 ms and
// twice the median, so a single slow probe does not read as an incident.
func slowSpans(samples []Sample, st Stats) []SlowSpan {
	threshold := int64(250)
	if twice := 2 * st.P50MS; twice > threshold {
		threshold = twice
	}
	out := []SlowSpan{}
	var cur *SlowSpan
	var sum int64
	for _, s := range samples {
		if !s.OK || s.MS < threshold {
			if cur != nil && cur.Checks >= 2 {
				cur.AvgMS = sum / int64(cur.Checks)
				out = append(out, *cur)
			}
			cur, sum = nil, 0
			continue
		}
		if cur == nil {
			cur = &SlowSpan{Start: s.At}
		}
		cur.End = s.At
		cur.Checks++
		sum += s.MS
		if s.MS > cur.MaxMS {
			cur.MaxMS = s.MS
		}
	}
	if cur != nil && cur.Checks >= 2 {
		cur.AvgMS = sum / int64(cur.Checks)
		out = append(out, *cur)
	}
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
