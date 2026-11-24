package proxy

import (
	"sync"
	"sync/atomic"
)

// size reports how many upstream pools are live, for the capacity report.
func (p *transportPool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

// capLimiter bounds concurrent requests for one site. A zero limit inherits the
// process-wide budget and imposes no extra bound.
type capLimiter struct {
	limit int
	n     atomic.Int64
	shed  atomic.Int64
}

func newCapLimiter(limit int) *capLimiter { return &capLimiter{limit: limit} }

// stats reports the requests this site holds and how many it has refused.
func (l *capLimiter) stats() (inflight int, shed int64) {
	if l == nil {
		return 0, 0
	}
	return int(l.n.Load()), l.shed.Load()
}

// acquire counts every request, limited or not: the count is what the capacity
// panel shows, and a site with no cap must not read as idle.
func (l *capLimiter) acquire() bool {
	if l == nil {
		return true
	}
	if l.limit > 0 && l.n.Load() >= int64(l.limit) {
		l.shed.Add(1)
		return false
	}
	l.n.Add(1)
	return true
}

func (l *capLimiter) release() {
	if l != nil {
		l.n.Add(-1)
	}
}

// clientLimiter bounds one client on one site, so a single source cannot spend
// the site's whole budget. Entries disappear when the client has no requests
// in flight.
type clientLimiter struct {
	mu     sync.Mutex
	limit  int
	counts map[string]int
	shed   int64
}

// shedTotal reports how many requests a client cap has refused.
func (l *clientLimiter) shedTotal() int64 {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.shed
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
		l.shed++
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
