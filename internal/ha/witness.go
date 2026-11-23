package ha

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// LeaseTTL is how long a witness grant lasts without renewal.
	LeaseTTL = 10 * time.Second
	// LeaseRenewEvery is the active's renewal period, comfortably inside TTL.
	LeaseRenewEvery = 3 * time.Second
)

// Lease is the witness's entire state: which node may write, under which epoch,
// until when. It stores nothing else, so it leaks nothing else.
type Lease struct {
	ClusterID string `json:"cluster_id"`
	Epoch     int64  `json:"epoch"`
	Holder    string `json:"holder"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Granted   bool   `json:"granted"`
	Error     string `json:"error,omitempty"`
}

type leaseRequest struct {
	ClusterID string `json:"cluster_id"`
	Epoch     int64  `json:"epoch"`
	Holder    string `json:"holder"`
}

// Witness grants one lease at a time. The token is required: a witness that
// answers anyone is a way to grant two actives.
type Witness struct {
	token string
	mu    sync.Mutex
	lease Lease
	// now is a seam for the expiry tests.
	now func() time.Time
}

// NewWitness returns a witness that requires the bearer token.
func NewWitness(token string) *Witness {
	return &Witness{token: token, now: time.Now}
}

// Handler exposes POST /ha/lease to acquire or renew and GET to inspect.
func (w *Witness) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ha/lease", w.grant)
	mux.HandleFunc("GET /ha/lease", w.current)
	return mux
}

func (w *Witness) authed(r *http.Request) bool {
	if w.token == "" {
		return false
	}
	want := "Bearer " + w.token
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) == 1
}

func (w *Witness) grant(rw http.ResponseWriter, r *http.Request) {
	if !w.authed(r) {
		writeJoinError(rw, http.StatusUnauthorized, "a witness token is required")
		return
	}
	var in leaseRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil ||
		in.ClusterID == "" || in.Holder == "" {
		writeJoinError(rw, http.StatusBadRequest, "cluster_id and holder are required")
		return
	}
	lease := w.acquire(in)
	status := http.StatusOK
	if !lease.Granted {
		status = http.StatusConflict
	}
	writeJoinJSON(rw, status, lease)
}

func (w *Witness) acquire(in leaseRequest) Lease {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	cur := w.lease
	live := cur.Holder != "" && now.Before(parseLeaseTime(cur.ExpiresAt))
	switch {
	case live && cur.ClusterID != in.ClusterID:
		return Lease{Granted: false, Error: "the witness holds a lease for another cluster"}
	case live && in.Epoch < cur.Epoch:
		return Lease{Granted: false, Error: fmt.Sprintf("epoch %d is below the held epoch %d", in.Epoch, cur.Epoch)}
	case live && in.Epoch == cur.Epoch && in.Holder != cur.Holder:
		return Lease{Granted: false, Error: fmt.Sprintf("epoch %d is held by %s", cur.Epoch, cur.Holder)}
	}
	w.lease = Lease{
		ClusterID: in.ClusterID, Epoch: in.Epoch, Holder: in.Holder,
		ExpiresAt: now.Add(LeaseTTL).UTC().Format(time.RFC3339Nano), Granted: true,
	}
	return w.lease
}

func (w *Witness) current(rw http.ResponseWriter, r *http.Request) {
	if !w.authed(r) {
		writeJoinError(rw, http.StatusUnauthorized, "a witness token is required")
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	lease := w.lease
	if lease.Holder == "" || !w.now().Before(parseLeaseTime(lease.ExpiresAt)) {
		lease.Granted = false
	}
	writeJoinJSON(rw, http.StatusOK, lease)
}

func parseLeaseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// Serve runs the witness until ctx ends. It is plain HTTP on the management
// network, guarded by the token; a TLS terminator in front is fine too.
func (w *Witness) Serve(ctx context.Context, addr string) error {
	if w.token == "" {
		return errors.New("ha: a witness token is required")
	}
	srv := &http.Server{
		Addr: addr, Handler: w.Handler(),
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// WitnessClient is the active's half: it asks one witness for the lease on its
// epoch.
type WitnessClient struct {
	URL       string
	Token     string
	ClusterID string
	Holder    string
	HTTP      *http.Client
}

// Acquire requests the lease for epoch. A refusal is an error, because the
// caller must treat "not granted" and "witness down" the same way.
func (c *WitnessClient) Acquire(ctx context.Context, epoch int64) (Lease, error) {
	httpc := c.HTTP
	if httpc == nil {
		httpc = &http.Client{Timeout: 3 * time.Second}
	}
	body, err := json.Marshal(leaseRequest{ClusterID: c.ClusterID, Epoch: epoch, Holder: c.Holder})
	if err != nil {
		return Lease{}, err
	}
	url := strings.TrimSuffix(c.URL, "/") + "/ha/lease"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Lease{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpc.Do(req)
	if err != nil {
		return Lease{}, fmt.Errorf("ha: witness %s: %w", c.URL, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var lease Lease
	if err := json.Unmarshal(raw, &lease); err != nil {
		return Lease{}, fmt.Errorf("ha: witness answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK || !lease.Granted {
		reason := lease.Error
		if reason == "" {
			reason = fmt.Sprintf("status %d", resp.StatusCode)
		}
		return lease, fmt.Errorf("ha: witness refused the lease: %s", reason)
	}
	return lease, nil
}

// LeaseKeeper renews the active's lease and reports the moment it is no longer
// safe to write. Renew failure alone is not loss: the lease stays valid until
// TTL, which absorbs a restart of the witness or a slow network.
type LeaseKeeper struct {
	Client *WitnessClient
	Epoch  int64
	Renew  time.Duration
	Now    func() time.Time
	OnLoss func(context.Context)

	mu        sync.Mutex
	lastGrant time.Time
}

// NewLeaseKeeper builds a keeper for one epoch.
func NewLeaseKeeper(c *WitnessClient, epoch int64) *LeaseKeeper {
	return &LeaseKeeper{Client: c, Epoch: epoch, Renew: LeaseRenewEvery, Now: time.Now}
}

// Tick renews once and reports whether the lease has been lost.
func (k *LeaseKeeper) Tick(ctx context.Context) bool {
	if _, err := k.Client.Acquire(ctx, k.Epoch); err == nil {
		k.mu.Lock()
		k.lastGrant = k.Now()
		k.mu.Unlock()
		return false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return !k.lastGrant.IsZero() && k.Now().Sub(k.lastGrant) > LeaseTTL
}

// Run renews until the lease is lost or ctx ends, then calls OnLoss once.
func (k *LeaseKeeper) Run(ctx context.Context) {
	ticker := time.NewTicker(k.Renew)
	defer ticker.Stop()
	for {
		if k.Tick(ctx) {
			if k.OnLoss != nil {
				k.OnLoss(ctx)
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
