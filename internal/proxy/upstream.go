package proxy

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

type upstream struct {
	url      *url.URL
	weight   int
	healthy  atomic.Bool
	inFlight atomic.Int64
	latency  atomic.Int64
	fails    atomic.Int32
}

func newUpstream(raw string, weight int) (*upstream, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		u.Scheme = "http"
	}
	up := &upstream{url: u, weight: weight}
	if up.weight <= 0 {
		up.weight = 1
	}
	up.healthy.Store(true)
	return up, nil
}

// pick selects an upstream using weighted round robin over healthy targets.
func pick(ups []*upstream, counter *uint64) *upstream {
	if len(ups) == 0 {
		return nil
	}
	healthy := make([]*upstream, 0, len(ups))
	total := 0
	for _, u := range ups {
		if u.healthy.Load() {
			healthy = append(healthy, u)
			total += u.weight
		}
	}
	if len(healthy) == 0 {
		return nil
	}
	if len(healthy) == 1 {
		return healthy[0]
	}
	n := atomic.AddUint64(counter, 1)
	slot := int(n % uint64(total))
	for _, u := range healthy {
		if slot < u.weight {
			return u
		}
		slot -= u.weight
	}
	return healthy[0]
}

// healthLoop probes upstreams until the context is cancelled.
func healthLoop(ctx context.Context, ups []*upstream, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext:       (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	probe := func() {
		var wg sync.WaitGroup
		for _, u := range ups {
			wg.Add(1)
			go func(u *upstream) {
				defer wg.Done()
				start := time.Now()
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.url.String()+"/", nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", "wafproxy-health/1.0")
				resp, err := client.Do(req)
				if err != nil {
					if u.fails.Add(1) >= 3 {
						u.healthy.Store(false)
					}
					return
				}
				_ = resp.Body.Close()
				u.fails.Store(0)
				u.latency.Store(time.Since(start).Milliseconds())
				u.healthy.Store(true)
			}(u)
		}
		wg.Wait()
	}
	probe()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			probe()
		}
	}
}
