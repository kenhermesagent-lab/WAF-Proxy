package proxy

import (
	"net/http"
	"sync"
	"testing"
)

// The request budget is the difference between a slow upstream and an outage:
// everything past WAFPROXY_MAX_INFLIGHT is refused at the door rather than
// buffered behind what is already in flight, and the split is exact.
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
