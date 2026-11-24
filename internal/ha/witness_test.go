package ha

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func witnessForTest(t *testing.T, token string) (*Witness, *httptest.Server, *time.Time) {
	t.Helper()
	w := NewWitness(token)
	now := time.Unix(1_700_000_000, 0)
	w.now = func() time.Time { return now }
	srv := httptest.NewServer(w.Handler())
	t.Cleanup(srv.Close)
	return w, srv, &now
}

func witnessClient(srv *httptest.Server, holder string) *WitnessClient {
	return &WitnessClient{
		URL: srv.URL, Token: "0123456789abcdef0123456789abcdef",
		ClusterID: "cluster-1", Holder: holder,
	}
}

const witnessTestToken = "0123456789abcdef0123456789abcdef"

func TestWitnessGrantsOneEpochToOneHolder(t *testing.T) {
	_, srv, now := witnessForTest(t, witnessTestToken)
	ctx := context.Background()
	a := witnessClient(srv, "node-a")
	b := witnessClient(srv, "node-b")

	if _, err := a.Acquire(ctx, 5); err != nil {
		t.Fatalf("first grant: %v", err)
	}
	// The holder renews its own epoch.
	if lease, err := a.Acquire(ctx, 5); err != nil || !lease.Granted {
		t.Fatalf("renew: %+v, %v", lease, err)
	}
	// A second holder at the same epoch is exactly the split brain the witness
	// exists to refuse.
	if _, err := b.Acquire(ctx, 5); err == nil || !strings.Contains(err.Error(), "held by node-a") {
		t.Fatalf("equal-epoch grant to B = %v", err)
	}
	if _, err := b.Acquire(ctx, 4); err == nil || !strings.Contains(err.Error(), "below") {
		t.Fatalf("lower-epoch grant to B = %v", err)
	}
	// A higher epoch wins, which is how the pair moves forward.
	if _, err := b.Acquire(ctx, 6); err != nil {
		t.Fatalf("higher-epoch grant to B: %v", err)
	}

	// After the lease expires, the same epoch is free again: the old holder was
	// required to stop writing when it could not renew.
	*now = now.Add(LeaseTTL + time.Second)
	if _, err := a.Acquire(ctx, 6); err != nil {
		t.Fatalf("grant after expiry: %v", err)
	}
}

func TestWitnessRequiresItsToken(t *testing.T) {
	_, srv, _ := witnessForTest(t, witnessTestToken)
	noToken := &WitnessClient{URL: srv.URL, ClusterID: "c", Holder: "n"}
	if _, err := noToken.Acquire(context.Background(), 1); err == nil {
		t.Fatal("a client without the token was granted a lease")
	}
	w := NewWitness("")
	if err := w.Serve(context.Background(), "127.0.0.1:0"); err == nil {
		t.Fatal("a witness without a token started")
	}
}

func TestLeaseKeeperDemotesWhenItNeverHeldTheLease(t *testing.T) {
	_, srv, _ := witnessForTest(t, witnessTestToken)
	keeper := NewLeaseKeeper(witnessClient(srv, "node-a"), 3)
	srv.Close()
	now := time.Unix(1_700_000_200, 0)
	keeper.Now = func() time.Time { return now }
	ctx := context.Background()

	if keeper.Tick(ctx) {
		t.Fatal("a keeper reported a loss before its first TTL")
	}
	now = now.Add(LeaseTTL + time.Second)
	if !keeper.Tick(ctx) {
		t.Fatal("an active that never obtained a lease did not report a loss")
	}
}

func TestLeaseKeeperDemotesOnlyAfterTTL(t *testing.T) {
	_, srv, _ := witnessForTest(t, witnessTestToken)
	keeper := NewLeaseKeeper(witnessClient(srv, "node-a"), 3)
	now := time.Unix(1_700_000_100, 0)
	keeper.Now = func() time.Time { return now }
	ctx := context.Background()

	if keeper.Tick(ctx) {
		t.Fatal("the first successful renewal reported a loss")
	}
	srv.Close()
	now = now.Add(5 * time.Second)
	if keeper.Tick(ctx) {
		t.Fatal("five seconds without the witness demoted the active")
	}
	now = now.Add(LeaseTTL)
	if !keeper.Tick(ctx) {
		t.Fatal("a lease older than the TTL did not report a loss")
	}
}
