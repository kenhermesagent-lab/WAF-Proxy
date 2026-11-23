package proxy

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The request budget is the difference between a slow upstream and an outage:
// everything past WAFPROXY_MAX_INFLIGHT is refused rather than buffered behind
// what is already in flight, and the split is exact.
func TestRequestBudgetShedsExactSplit(t *testing.T) {
	h := newHarness(t)
	const budget, burst = 3, 9
	h.px.SetMaxInflight(budget)

	type result struct {
		code       int
		retryAfter string
	}
	results := make([]result, burst)
	var ready sync.WaitGroup
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < burst; i++ {
		wg.Add(1)
		ready.Add(1)
		go func(i int) {
			defer wg.Done()
			ready.Done()
			<-start
			rec := h.request(http.MethodGet, testHost, "/slow", "", nil)
			results[i] = result{code: rec.Code, retryAfter: rec.Header().Get("Retry-After")}
		}(i)
	}
	ready.Wait()
	close(start)
	wg.Wait()

	ok, shed := 0, 0
	for _, r := range results {
		switch r.code {
		case http.StatusOK:
			ok++
		case http.StatusServiceUnavailable:
			shed++
			if r.retryAfter == "" {
				t.Error("a refused request carries no Retry-After")
			}
		default:
			t.Fatalf("unexpected status %d", r.code)
		}
	}
	if ok != budget {
		t.Fatalf("%d requests were served, want exactly the budget of %d", ok, budget)
	}
	if shed != burst-budget {
		t.Fatalf("%d requests were refused, want %d", shed, burst-budget)
	}
	inflight, max, refused := h.px.Capacity()
	if max != budget || inflight != 0 || refused != burst-budget {
		t.Fatalf("capacity = inflight %d, max %d, shed %d; want 0, %d, %d",
			inflight, max, refused, budget, burst-budget)
	}
	if hits := h.hits.Load(); hits != budget {
		t.Fatalf("upstream saw %d requests, want the %d that held a slot", hits, budget)
	}
}

// A burst that lasts less than the queue window is absorbed, not shed: this is
// the whole reason the budget waits instead of refusing at the door.
func TestBudgetQueueServesWhenRoomAppears(t *testing.T) {
	b := newBudget(1, 1<<20)
	first, reason := b.reserve(context.Background(), 0, 200*time.Millisecond)
	if first == nil {
		t.Fatalf("the first request was refused: %q", reason)
	}
	admitted := make(chan bool, 1)
	go func() {
		release, _ := b.reserve(context.Background(), 0, 200*time.Millisecond)
		admitted <- release != nil
		if release != nil {
			release()
		}
	}()
	time.Sleep(50 * time.Millisecond)
	first()
	if !<-admitted {
		t.Fatal("a queued request was not served when a slot came free")
	}
}

// queue_ms=0 restores the pre-queue behaviour: refuse at once, no waiting.
func TestBudgetZeroQueueShedsAtOnce(t *testing.T) {
	b := newBudget(1, 1<<20)
	held, _ := b.reserve(context.Background(), 0, 0)
	if held == nil {
		t.Fatal("the first request was refused")
	}
	start := time.Now()
	if _, reason := b.reserve(context.Background(), 0, 0); reason != "queue" {
		t.Fatalf("reason = %q, want queue", reason)
	}
	if waited := time.Since(start); waited > 100*time.Millisecond {
		t.Fatalf("a request with no queue waited %s", waited)
	}
	held()
	if _, _, _, _, shed := b.snapshot(); shed != 1 {
		t.Fatalf("shed = %d, want 1", shed)
	}
}

// The byte ceiling holds even when the count has room: one big upload must not
// be admitted just because the connection count is low.
func TestBudgetBytesCeiling(t *testing.T) {
	b := newBudget(100, 1000)
	ctx := context.Background()
	first, _ := b.reserve(ctx, 600, 20*time.Millisecond)
	second, _ := b.reserve(ctx, 400, 20*time.Millisecond)
	if first == nil || second == nil {
		t.Fatal("a request that fits the byte ceiling was refused")
	}
	if _, reason := b.reserve(ctx, 1, 20*time.Millisecond); reason != "queue" {
		t.Fatalf("an over-ceiling request was admitted (reason %q)", reason)
	}
	first()
	second()
	if _, _, used, _, _ := b.snapshot(); used != 0 {
		t.Fatalf("bytes = %d after both releases, want 0", used)
	}
}

// The whole estimate comes back when the request ends, however small the body
// turned out to be.
func TestBudgetReleasesTheWholeReservation(t *testing.T) {
	b := newBudget(10, 1<<20)
	release, _ := b.reserve(context.Background(), 64<<10, 20*time.Millisecond)
	if release == nil {
		t.Fatal("the request was refused")
	}
	release()
	if count, _, used, _, _ := b.snapshot(); count != 0 || used != 0 {
		t.Fatalf("after settling: count %d, bytes %d; want 0, 0", count, used)
	}
}

// A thousand concurrent reservations never exceed the ceiling, and every one of
// them gives its bytes back.
func TestBudgetConcurrentStaysUnderCeiling(t *testing.T) {
	const ceiling = 64 << 10
	b := newBudget(1000, ceiling)
	var peak atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, _ := b.reserve(context.Background(), 1024, 200*time.Millisecond)
			if release == nil {
				return
			}
			if _, _, used, _, _ := b.snapshot(); used > peak.Load() {
				peak.Store(used)
			}
			release()
		}()
	}
	wg.Wait()
	if peak.Load() > ceiling {
		t.Fatalf("peak bytes = %d, above the %d ceiling", peak.Load(), ceiling)
	}
	if _, _, used, _, _ := b.snapshot(); used != 0 {
		t.Fatalf("bytes = %d after the run, want 0", used)
	}
}
