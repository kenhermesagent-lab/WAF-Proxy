package policy

import (
	"sync"
	"time"
)

type bucket struct {
	tokens  float64
	last    time.Time
	strikes []time.Time
}

type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	reqs    int64
	window  time.Time
}

func newLimiter() *limiter {
	return &limiter{
		buckets: map[string]*bucket{},
		window:  time.Now(),
	}
}

// Allow consumes a token for key. It returns whether the request is allowed and
// whether the caller should escalate to a short ban (three denials in a minute).
func (l *limiter) Allow(key string, rps, burst int, now time.Time) (bool, bool) {
	if rps <= 0 {
		return true, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(burst), last: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * float64(rps)
		if b.tokens > float64(burst) {
			b.tokens = float64(burst)
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, false
	}
	cutoff := now.Add(-time.Minute)
	kept := b.strikes[:0]
	for _, t := range b.strikes {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	b.strikes = append(kept, now)
	return false, len(b.strikes) >= 3
}

func (l *limiter) noteTraffic() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.window) > time.Second {
		l.window = now
		l.reqs = 0
	}
	l.reqs++
}

func (l *limiter) shouldSample(limit int) bool {
	if limit <= 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	perSecond := l.reqs
	return perSecond > int64(limit)
}

// Cleanup drops idle buckets; call periodically. Strike timestamps are pruned
// first, because a bucket that ever denied a request would otherwise keep its
// slice forever and never become deletable.
func (l *limiter) Cleanup() {
	now := time.Now()
	cutoff := now.Add(-10 * time.Minute)
	strikeCutoff := now.Add(-time.Minute)
	l.mu.Lock()
	for k, b := range l.buckets {
		kept := b.strikes[:0]
		for _, t := range b.strikes {
			if t.After(strikeCutoff) {
				kept = append(kept, t)
			}
		}
		b.strikes = kept
		if b.last.Before(cutoff) && len(b.strikes) == 0 {
			delete(l.buckets, k)
		}
	}
	l.mu.Unlock()
}
