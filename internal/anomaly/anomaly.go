// Package anomaly turns the per-proxy counters into detections: an outbound
// byte spike, a request-rate spike, or a burst of failed gate logins.
package anomaly

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/netmatch"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// Window is the detection period: one minute of counters, compared with the
// same proxy's recent windows.
const Window = time.Minute

// MutesKey stores the flows an operator expects: destinations traffic goes to
// and whitelisted sources it comes from.
const MutesKey = "anomaly_mutes"

// Mute kinds. A destination is an upstream host, without its port; a source is
// one address or CIDR from an enabled IP whitelist.
const (
	MuteDestination = "destination"
	MuteSource      = "source"
)

// ValidMuteKind reports whether kind is a flow the detector can mute.
func ValidMuteKind(kind string) bool {
	return kind == MuteDestination || kind == MuteSource
}

// Mute is one flow whose traffic is expected, so an outbound spike made only of
// it is not a detection.
type Mute struct {
	ProxyID int64     `json:"proxy_id"`
	Kind    string    `json:"kind"` // destination | source
	Address string    `json:"address"`
	At      time.Time `json:"at"`
}

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
	sink   func(model.AnomalyEvent)

	mu   sync.Mutex
	prev map[int64]sample
	// srcPrev is each proxy's per-source outbound totals as of the previous
	// tick, so a window can be attributed to the clients that moved it.
	srcPrev map[int64]map[string]int64
	egress  map[int64][]float64
	rates   map[int64][]float64
}

// New returns a detector bound to the store and the metrics collector.
func New(st *store.Store, met *metrics.Collector, notify Notifier, log *slog.Logger) *Manager {
	return &Manager{
		st: st, met: met, notify: notify, log: log, now: time.Now,
		prev:    map[int64]sample{},
		srcPrev: map[int64]map[string]int64{},
		egress:  map[int64][]float64{},
		rates:   map[int64][]float64{},
	}
}

// SetSink attaches a delivery hook, used to push the event to agent webhooks.
func (m *Manager) SetSink(sink func(model.AnomalyEvent)) { m.sink = sink }

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

// Mutes lists the destinations traffic is expected to reach.
func (m *Manager) Mutes() ([]Mute, error) {
	kv, err := m.st.Settings()
	if err != nil {
		return nil, err
	}
	out := []Mute{}
	if raw := strings.TrimSpace(kv[MutesKey]); raw != "" {
		// An unreadable row loses the mutes, not the whole page.
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			return []Mute{}, nil
		}
	}
	for i := range out {
		// Entries written before sources existed are destination mutes.
		if out[i].Kind == "" {
			out[i].Kind = MuteDestination
		}
	}
	return out, nil
}

// AddMute records one expected flow: a destination the site sends to, or a
// whitelisted source it accepts from. The same flow twice is one entry, so
// muting from two events cannot leave stale copies behind.
func (m *Manager) AddMute(proxyID int64, kind, address string) error {
	address = strings.TrimSpace(address)
	if kind == "" {
		kind = MuteDestination
	}
	if proxyID == 0 || address == "" {
		return errors.New("a mute needs a proxy and an address")
	}
	if !ValidMuteKind(kind) {
		return errors.New("a mute is for a destination or a source")
	}
	mutes, err := m.Mutes()
	if err != nil {
		return err
	}
	for _, mu := range mutes {
		if mu.ProxyID == proxyID && mu.Kind == kind && mu.Address == address {
			return nil
		}
	}
	mutes = append(mutes, Mute{ProxyID: proxyID, Kind: kind, Address: address, At: m.now().UTC()})
	return m.saveMutes(mutes)
}

// RemoveMute forgets one expected flow, so its spikes are detected again.
func (m *Manager) RemoveMute(proxyID int64, kind, address string) error {
	if kind == "" {
		kind = MuteDestination
	}
	mutes, err := m.Mutes()
	if err != nil {
		return err
	}
	kept := mutes[:0]
	for _, mu := range mutes {
		if mu.ProxyID == proxyID && mu.Kind == kind && mu.Address == address {
			continue
		}
		kept = append(kept, mu)
	}
	return m.saveMutes(kept)
}

func (m *Manager) saveMutes(mutes []Mute) error {
	if mutes == nil {
		mutes = []Mute{}
	}
	blob, err := json.Marshal(mutes)
	if err != nil {
		return err
	}
	return m.st.SetSetting(MutesKey, string(blob))
}

// expectedEgress reports whether a window's outbound traffic is the traffic an
// operator said to expect. A site counts as expected when every enabled
// upstream is a muted destination, or when every byte the window sent came from
// a muted source. A destination or a client nobody muted keeps the spike, and
// so does a byte the counters could not attribute.
func (m *Manager) expectedEgress(proxyID, total int64, bySource map[string]int64) bool {
	mutes, err := m.Mutes()
	if err != nil {
		m.log.Warn("anomaly mute lookup failed", "err", err)
		return false
	}
	dest := map[string]bool{}
	muted := []netip.Prefix{}
	for _, mu := range mutes {
		if mu.ProxyID != proxyID {
			continue
		}
		if mu.Kind == MuteSource {
			// A whitelist entry may be a subnet, so it matches the clients
			// inside it and not only the address it was written as.
			if p, err := netmatch.ParsePrefix(mu.Address); err == nil {
				muted = append(muted, p)
			}
			continue
		}
		dest[mu.Address] = true
	}
	if len(dest) > 0 && m.allDestinationsMuted(proxyID, dest) {
		return true
	}
	if len(muted) == 0 {
		return false
	}
	var accounted, fromMuted int64
	for addr, bytes := range bySource {
		accounted += bytes
		a, err := netip.ParseAddr(addr)
		if err != nil {
			continue
		}
		for _, p := range muted {
			if p.Contains(a) {
				fromMuted += bytes
				break
			}
		}
	}
	// Bytes no source accounts for could be anyone's, so they are never
	// expected; the same goes for a window that only partly came from muted
	// sources.
	return accounted == total && fromMuted == total
}

// allDestinationsMuted reports whether every enabled upstream of a proxy is a
// muted destination. Without an enabled upstream there is nothing to match.
func (m *Manager) allDestinationsMuted(proxyID int64, muted map[string]bool) bool {
	ups, err := m.st.ListUpstreams(proxyID)
	if err != nil {
		return false
	}
	checked := 0
	for _, up := range ups {
		if !up.Enabled {
			continue
		}
		checked++
		if !muted[upstreamHost(up.URL)] {
			return false
		}
	}
	return checked > 0
}

// sourceWindow returns the outbound bytes each client moved since the previous
// tick, and remembers this tick's totals for the next one.
func (m *Manager) sourceWindow(proxyID int64) map[string]int64 {
	now := m.met.EgressBySource(proxyID)
	prev := m.srcPrev[proxyID]
	out := map[string]int64{}
	for addr, total := range now {
		if grown := total - prev[addr]; grown > 0 {
			out[addr] = grown
		}
	}
	m.srcPrev[proxyID] = now
	return out
}

// upstreamHost is the host an upstream URL sends traffic to, without its port.
func upstreamHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
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
		bySource := m.sourceWindow(id)
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
		if float64(out) >= floor && float64(out) >= cfg.EgressFactor*egressBase && !m.expectedEgress(id, out, bySource) {
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
	id, err := m.st.CreateAnomalyEvent(&e)
	if err != nil {
		m.log.Warn("anomaly store failed", "err", err)
		return
	}
	e.ID = id
	m.notify.Enqueue(e.Kind, describe(e), "anomaly:"+e.Kind+":"+strconv.FormatInt(e.ProxyID, 10), true)
	if m.sink != nil {
		m.sink(e)
	}
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
