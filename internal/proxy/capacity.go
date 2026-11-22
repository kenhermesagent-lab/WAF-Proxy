package proxy

import "sync"

// capLimiter bounds concurrent requests for one site. A zero limit inherits the
// process-wide budget and imposes no extra bound.
type capLimiter struct {
	mu    sync.Mutex
	limit int
	n     int
}

func newCapLimiter(limit int) *capLimiter { return &capLimiter{limit: limit} }

func (l *capLimiter) acquire() bool {
	if l == nil || l.limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n >= l.limit {
		return false
	}
	l.n++
	return true
}

func (l *capLimiter) release() {
	if l == nil || l.limit <= 0 {
		return
	}
	l.mu.Lock()
	if l.n > 0 {
		l.n--
	}
	l.mu.Unlock()
}

// clientLimiter bounds one client on one site, so a single source cannot spend
// the site's whole budget. Entries disappear when the client has no requests
// in flight.
type clientLimiter struct {
	mu     sync.Mutex
	limit  int
	counts map[string]int
}

func newClientLimiter(limit int) *clientLimiter {
	return &clientLimiter{limit: limit, counts: map[string]int{}}
}

func (l *clientLimiter) acquire(key string) bool {
	if l == nil || l.limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[key] >= l.limit {
		return false
	}
	l.counts[key]++
	return true
}

func (l *clientLimiter) release(key string) {
	if l == nil || l.limit <= 0 {
		return
	}
	l.mu.Lock()
	if l.counts[key] <= 1 {
		delete(l.counts, key)
	} else {
		l.counts[key]--
	}
	l.mu.Unlock()
}
