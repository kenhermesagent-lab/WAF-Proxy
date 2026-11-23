package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"hash/fnv"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// Balancing policies. The default keeps the historical weighted round robin.
const (
	LBWeightedRR   = "weighted_rr"
	LBLeastConn    = "least_conn"
	LBLeastLatency = "least_latency"
	LBIPHash       = "ip_hash"
	LBStickyCookie = "sticky_cookie"
)

// stickyCookie pins a visitor to one upstream. It carries no personal data,
// only a keyed digest of the upstream URL, and is meaningless after a restart.
const stickyCookie = "wpx_upstream"

type upstream struct {
	url      *url.URL
	weight   int
	maxConns int64
	healthy  atomic.Bool
	inFlight atomic.Int64
	latency  atomic.Int64 // milliseconds, 0 until measured
	fails    atomic.Int32
	// ejectedUntil is when a passively ejected upstream may be probed again.
	ejectedUntil atomic.Int64
}

func newUpstream(raw string, weight, maxConns int) (*upstream, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		u.Scheme = "http"
	}
	up := &upstream{url: u, weight: weight, maxConns: int64(maxConns)}
	if up.weight <= 0 {
		up.weight = 1
	}
	up.healthy.Store(true)
	return up, nil
}

// statusExpect is the set of probe status codes considered healthy.
type statusExpect struct{ ranges [][2]int }

func parseStatusExpect(s string) statusExpect {
	parsed := statusExpect{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi := part, part
		if i := strings.IndexByte(part, '-'); i >= 0 {
			lo, hi = part[:i], part[i+1:]
		}
		a, err1 := strconv.Atoi(strings.TrimSpace(lo))
		b, err2 := strconv.Atoi(strings.TrimSpace(hi))
		if err1 != nil || err2 != nil || a < 100 || b > 599 || a > b {
			continue
		}
		parsed.ranges = append(parsed.ranges, [2]int{a, b})
	}
	if len(parsed.ranges) == 0 {
		parsed.ranges = [][2]int{{200, 399}}
	}
	return parsed
}

func (e statusExpect) ok(code int) bool {
	for _, r := range e.ranges {
		if code >= r[0] && code <= r[1] {
			return true
		}
	}
	return false
}

// healthSettings is one site's probe configuration. Upstreams inherit it.
type healthSettings struct {
	path      string
	expect    statusExpect
	interval  time.Duration
	cooldown  time.Duration
	failAfter int32
}

func healthFor(p model.Proxy) healthSettings {
	h := healthSettings{
		path:      p.HealthPath,
		expect:    parseStatusExpect(p.HealthExpect),
		interval:  time.Duration(p.HealthInterval) * time.Second,
		failAfter: int32(p.HealthFailAfter),
	}
	if h.path == "" {
		h.path = "/"
	}
	if h.interval <= 0 {
		h.interval = 10 * time.Second
	}
	if h.failAfter <= 0 {
		h.failAfter = 3
	}
	h.cooldown = 3 * h.interval / 2
	return h
}

func eligible(u *upstream) bool {
	if !u.healthy.Load() {
		return false
	}
	return u.maxConns <= 0 || u.inFlight.Load() < u.maxConns
}

func healthyList(ups []*upstream) []*upstream {
	out := make([]*upstream, 0, len(ups))
	for _, u := range ups {
		if eligible(u) {
			out = append(out, u)
		}
	}
	return out
}

// pick selects an upstream with the configured policy. Only healthy upstreams
// below their connection cap are candidates.
func pick(ups []*upstream, counter *uint64, policy, clientKey string) *upstream {
	candidates := healthyList(ups)
	if len(candidates) == 0 {
		return nil
	}
	n := atomic.AddUint64(counter, 1)
	switch policy {
	case LBLeastConn:
		best := candidates[0]
		for _, u := range candidates[1:] {
			if u.inFlight.Load() < best.inFlight.Load() {
				best = u
			}
		}
		return best
	case LBLeastLatency:
		best := candidates[0]
		for _, u := range candidates[1:] {
			if latencyOf(u) < latencyOf(best) {
				best = u
			}
		}
		return best
	case LBIPHash:
		key := clientKey
		if key == "" {
			key = strconv.FormatUint(n, 10)
		}
		h := fnv.New32a()
		_, _ = h.Write([]byte(key))
		return candidates[h.Sum32()%uint32(len(candidates))]
	}
	total := 0
	for _, u := range candidates {
		total += u.weight
	}
	slot := int(n % uint64(total))
	for _, u := range candidates {
		if slot < u.weight {
			return u
		}
		slot -= u.weight
	}
	return candidates[0]
}

func latencyOf(u *upstream) int64 {
	if ms := u.latency.Load(); ms > 0 {
		return ms
	}
	return 1 << 40 // unmeasured backends go last
}

var stickyKey = func() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}()

func stickyTag(u *upstream) string {
	mac := hmac.New(sha256.New, stickyKey)
	_, _ = mac.Write([]byte(u.url.String()))
	return hex.EncodeToString(mac.Sum(nil)[:12])
}

func stickyUpstream(ups []*upstream, tag string) *upstream {
	if tag == "" {
		return nil
	}
	for _, u := range ups {
		if eligible(u) && hmac.Equal([]byte(stickyTag(u)), []byte(tag)) {
			return u
		}
	}
	return nil
}

// selectUpstream applies the site's policy, honouring a sticky cookie.
func selectUpstream(e *edge, r *http.Request, w http.ResponseWriter) *upstream {
	policy := e.proxy.LBPolicy
	var up *upstream
	if policy == LBStickyCookie {
		if c, err := r.Cookie(stickyCookie); err == nil {
			up = stickyUpstream(e.ups, c.Value)
		}
	}
	if up == nil {
		up = pick(e.ups, &e.rr, policy, clientAddr(r).String())
	}
	if up != nil && policy == LBStickyCookie {
		http.SetCookie(w, &http.Cookie{
			Name: stickyCookie, Value: stickyTag(up), Path: "/",
			MaxAge: 86400, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
	}
	return up
}

// upstreamFor returns the upstream a route names, so one rule can target a
// different backend without leaving the site's pool.
func (e *edge) upstreamFor(raw string) *upstream {
	want := strings.TrimRight(strings.TrimSpace(raw), "/")
	for _, u := range e.ups {
		if strings.TrimRight(u.url.String(), "/") == want {
			return u
		}
	}
	return nil
}

// noteFailure ejects an upstream after enough consecutive failures. A passive
// failure (a real 5xx or a transport error) uses the same counter as a probe.
func (u *upstream) noteFailure(cfg healthSettings) {
	if u.fails.Add(1) >= cfg.failAfter {
		u.healthy.Store(false)
		u.ejectedUntil.Store(time.Now().Add(cfg.cooldown).UnixNano())
	}
}

func (u *upstream) noteSuccess(latency time.Duration) {
	u.fails.Store(0)
	if latency > 0 {
		u.latency.Store(latency.Milliseconds())
	}
	u.ejectedUntil.Store(0)
	u.healthy.Store(true)
}

// healthLoop probes upstreams until the context is cancelled.
func healthLoop(ctx context.Context, ups []*upstream, cfg healthSettings) {
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext:       (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	probeOnce(ctx, client, ups, cfg)
	t := time.NewTicker(cfg.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			probeOnce(ctx, client, ups, cfg)
		}
	}
}

// probeOnce checks every upstream once. An ejected upstream is given a single
// half-open probe when its cooldown has passed, so recovery needs one success
// rather than a full threshold.
func probeOnce(ctx context.Context, client *http.Client, ups []*upstream, cfg healthSettings) {
	now := time.Now()
	var wg sync.WaitGroup
	for _, u := range ups {
		wg.Add(1)
		go func(u *upstream) {
			defer wg.Done()
			if !u.healthy.Load() && now.UnixNano() >= u.ejectedUntil.Load() {
				u.healthy.Store(true)
			}
			start := time.Now()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.url.String()+cfg.path, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "wafproxy-health/1.0")
			resp, err := client.Do(req)
			if err != nil {
				u.noteFailure(cfg)
				return
			}
			_ = resp.Body.Close()
			if !cfg.expect.ok(resp.StatusCode) {
				u.noteFailure(cfg)
				return
			}
			u.noteSuccess(time.Since(start))
		}(u)
	}
	wg.Wait()
}
