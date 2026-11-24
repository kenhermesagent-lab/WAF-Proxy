package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// countingListener records the connections it accepted and how many of them are
// still open, so a test can see a pool close its idle ones.
type countingListener struct {
	net.Listener
	opened atomic.Int32
	open   atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.opened.Add(1)
	l.open.Add(1)
	return &countedConn{Conn: c, l: l}, nil
}

type countedConn struct {
	net.Conn
	l    *countingListener
	once sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() { c.l.open.Add(-1) })
	return c.Conn.Close()
}

func countingUpstream(t *testing.T) (*httptest.Server, *countingListener) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("upstream"))
	}))
	cl := &countingListener{Listener: srv.Listener}
	srv.Listener = cl
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, cl
}

func (h *harness) useUpstream(t *testing.T, url string) {
	t.Helper()
	ups := []model.Upstream{{ProxyID: h.proxy.ID, URL: url, Weight: 1, Enabled: true}}
	if err := h.st.ReplaceUpstreams(h.proxy.ID, ups); err != nil {
		t.Fatal(err)
	}
	if err := h.px.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// A reload of an unchanged upstream must keep every warm connection, and moving
// the route to another origin must open a fresh one and let the old pool go.
func TestReloadKeepsWarmUpstreamConnections(t *testing.T) {
	h := newHarness(t)
	var dials atomic.Int32
	base := h.px.pool.dial
	h.px.pool.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return base(ctx, network, addr)
	}
	a, counted := countingUpstream(t)
	h.useUpstream(t, a.URL)

	get := func() {
		t.Helper()
		if rec := h.request(http.MethodGet, testHost, "/", "", nil); rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
	}
	get()
	get()
	warm := dials.Load()
	if warm == 0 {
		t.Fatal("nothing dialled the upstream")
	}
	for i := 0; i < 2; i++ {
		if err := h.px.Reload(context.Background()); err != nil {
			t.Fatal(err)
		}
		get()
	}
	if got := dials.Load(); got != warm {
		t.Fatalf("two reloads added %d upstream connections, want 0", got-warm)
	}

	b, bCounted := countingUpstream(t)
	h.useUpstream(t, b.URL)
	get()
	if bCounted.opened.Load() == 0 {
		t.Fatal("the changed upstream was never dialled")
	}
	deadline := time.Now().Add(2 * time.Second)
	for counted.open.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := counted.open.Load(); n != 0 {
		t.Fatalf("%d idle connections to the removed upstream are still open", n)
	}
}

func newTestDNSCache(resolve func(context.Context, string) ([]string, error), now func() time.Time) *dnsCache {
	return &dnsCache{resolve: resolve, now: now, ttl: time.Second, stale: 5 * time.Minute, hosts: map[string]*dnsEntry{}}
}

func TestDNSCacheReResolvesAfterTheTTL(t *testing.T) {
	var calls atomic.Int32
	now := time.Unix(1000, 0)
	c := newTestDNSCache(func(context.Context, string) ([]string, error) {
		return []string{"203.0.113." + strconv.Itoa(int(calls.Add(1)))}, nil
	}, func() time.Time { return now })

	first, err := c.lookup(context.Background(), "origin.test")
	if err != nil || len(first) != 1 {
		t.Fatalf("first lookup = %v, %v", first, err)
	}
	if again, _ := c.lookup(context.Background(), "origin.test"); again[0] != first[0] {
		t.Fatalf("a fresh answer was not reused: %v then %v", first, again)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("resolver called %d times inside the TTL, want 1", got)
	}
	now = now.Add(2 * time.Second)
	if third, err := c.lookup(context.Background(), "origin.test"); err != nil || third[0] == first[0] {
		t.Fatalf("after the TTL the lookup = %v, %v; want the new address", third, err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("resolver called %d times after the TTL, want 2", got)
	}
}

func TestDNSCacheServesTheLastGoodAnswerThroughAnOutage(t *testing.T) {
	var failing atomic.Bool
	now := time.Unix(2000, 0)
	c := newTestDNSCache(func(context.Context, string) ([]string, error) {
		if failing.Load() {
			return nil, errors.New("resolver unreachable")
		}
		return []string{"198.51.100.7"}, nil
	}, func() time.Time { return now })
	if _, err := c.lookup(context.Background(), "origin.test"); err != nil {
		t.Fatal(err)
	}
	failing.Store(true)
	now = now.Add(2 * time.Second) // the TTL is over and the resolver is down
	addrs, err := c.lookup(context.Background(), "origin.test")
	if err != nil || len(addrs) != 1 || addrs[0] != "198.51.100.7" {
		t.Fatalf("outage inside five minutes lost the last good address: %v, %v", addrs, err)
	}
	now = now.Add(6 * time.Minute)
	if _, err := c.lookup(context.Background(), "origin.test"); err == nil {
		t.Fatal("the stale answer outlived its five-minute window")
	}
}

// A cached answer with both families must not wait for a dead IPv6 address: the
// two families are dialled at once, the way net.Dialer falls back.
func TestDNSDialRacesFamiliesSoABrokenIPv6StallsNothing(t *testing.T) {
	c := newTestDNSCache(func(context.Context, string) ([]string, error) {
		return []string{"2001:db8::1", "198.51.100.7"}, nil
	}, time.Now)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	c.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "[2001:db8::1]") {
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
			return nil, errors.New("no route to host")
		}
		return local, nil
	}
	start := time.Now()
	conn, err := c.dialContext(context.Background(), "tcp", "origin.test:8080")
	if err != nil || conn != local {
		t.Fatalf("dial = %v, %v; want the IPv4 connection", conn, err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("the broken IPv6 address held the dial for %s", elapsed)
	}
}

func TestDNSCacheResolvesOneHostOnce(t *testing.T) {
	var calls atomic.Int32
	c := newTestDNSCache(func(context.Context, string) ([]string, error) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		return []string{"198.51.100.7"}, nil
	}, time.Now)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.lookup(context.Background(), "origin.test"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("eight concurrent lookups asked the resolver %d times, want 1", got)
	}
}
