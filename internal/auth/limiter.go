package auth

import (
	"sync"
	"time"
)

type bucket struct {
	count int
	reset time.Time
}

// Limiter is a fixed-window counter keyed by an arbitrary string.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

// NewLimiter returns an empty limiter.
func NewLimiter() *Limiter {
	return &Limiter{buckets: map[string]*bucket{}}
}

// Allow consumes one unit for key and reports whether it was within limit.
// A limit of zero or less always allows.
func (l *Limiter) Allow(key string, limit int, window time.Duration) bool {
	if limit <= 0 {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok || now.After(b.reset) {
		l.buckets[key] = &bucket{count: 1, reset: now.Add(window)}
		return true
	}
	if b.count >= limit {
		return false
	}
	b.count++
	return true
}

// Count returns the current count without consuming a unit.
func (l *Limiter) Count(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok || time.Now().After(b.reset) {
		return 0
	}
	return b.count
}

// Reset clears a key, used after a successful login.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	delete(l.buckets, key)
	l.mu.Unlock()
}

// Cleanup drops expired buckets and is meant to run periodically.
func (l *Limiter) Cleanup() {
	now := time.Now()
	l.mu.Lock()
	for k, b := range l.buckets {
		if now.After(b.reset) {
			delete(l.buckets, k)
		}
	}
	l.mu.Unlock()
}
