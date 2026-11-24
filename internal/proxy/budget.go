package proxy

import (
	"context"
	"sync"
	"time"
)

// budget bounds the requests buffered at once by count and by bytes. A count
// alone cannot bound memory — 128 requests holding an 8 MiB body is a gigabyte —
// and it is reached long before the CPUs are busy. A request waits for room for
// a short, bounded time instead of being shed on the first miss, because a 50 ms
// burst is not an outage.
type budget struct {
	mu       sync.Mutex
	count    int64
	bytes    int64
	queued   int64
	maxCount int64
	maxBytes int64
	// Refusals are split by reason, because "the request was too big" and "the
	// queue ran out" need different answers from the operator.
	shedBytes int64
	shedQueue int64
	// changed is closed and replaced whenever a slot is given back, so waiters
	// sleep without a condition variable.
	changed chan struct{}
}

func newBudget(maxCount, maxBytes int64) *budget {
	if maxCount <= 0 {
		maxCount = DefaultMaxInflight
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBufferedBytes
	}
	return &budget{maxCount: maxCount, maxBytes: maxBytes, changed: make(chan struct{})}
}

func (b *budget) setCount(n int64) {
	if n <= 0 {
		n = DefaultMaxInflight
	}
	b.mu.Lock()
	b.maxCount = n
	b.wake()
	b.mu.Unlock()
}

func (b *budget) setLimits(maxBytes int64) {
	b.mu.Lock()
	if maxBytes > 0 {
		b.maxBytes = maxBytes
	}
	b.wake()
	b.mu.Unlock()
}

// reserve takes size bytes out of the budget, waiting up to wait for room. It
// returns a release function and an empty reason, or no release function and the
// reason the request was shed: "bytes" when the request alone cannot fit,
// "queue" when the wait ran out.
func (b *budget) reserve(ctx context.Context, size int64, wait time.Duration) (func(), string) {
	b.mu.Lock()
	if size > b.maxBytes {
		b.shedBytes++
		b.mu.Unlock()
		return nil, "bytes"
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		if b.count < b.maxCount && b.bytes+size <= b.maxBytes {
			b.count++
			b.bytes += size
			b.mu.Unlock()
			return b.release(size), ""
		}
		b.queued++
		changed := b.changed
		b.mu.Unlock()
		refused := false
		select {
		case <-changed:
		case <-ctx.Done():
			refused = true
		case <-timer.C:
			refused = true
		}
		b.mu.Lock()
		b.queued--
		if refused {
			b.shedQueue++
			b.mu.Unlock()
			return nil, "queue"
		}
	}
}

// release gives the reservation back once the request is done. The estimate is
// what the request could hold, not what it did: an unknown length is capped at
// 64 KiB, so the over-reservation is bounded and dies with the request.
func (b *budget) release(reserved int64) func() {
	return func() {
		b.mu.Lock()
		b.count--
		b.bytes -= reserved
		b.wake()
		b.mu.Unlock()
	}
}

// wake hands the lock-free waiters a fresh channel while the caller still holds
// the mutex.
func (b *budget) wake() {
	close(b.changed)
	b.changed = make(chan struct{})
}

// budgetState is what the capacity panel and /metrics read.
type budgetState struct {
	count, maxCount, bytes, maxBytes, queued int64
	shedBytes, shedQueue                     int64
}

func (b *budget) snapshot() budgetState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return budgetState{count: b.count, maxCount: b.maxCount, bytes: b.bytes, maxBytes: b.maxBytes,
		queued: b.queued, shedBytes: b.shedBytes, shedQueue: b.shedQueue}
}
