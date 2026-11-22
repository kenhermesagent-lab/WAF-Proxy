package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func newFlaky(base http.RoundTripper, retries int) *retryTransport {
	return &retryTransport{base: base, retries: retries}
}

func TestRetryGetsIdempotentRequest(t *testing.T) {
	var attempts atomic.Int32
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if attempts.Add(1) < 3 {
			return responseWith(r, http.StatusServiceUnavailable), nil
		}
		return responseWith(r, http.StatusOK), nil
	})
	req, _ := http.NewRequest(http.MethodGet, "http://upstream.test/", nil)
	res, err := newFlaky(base, 3).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK || attempts.Load() != 3 {
		t.Fatalf("got status %d after %d attempts", res.StatusCode, attempts.Load())
	}
}

func TestRetrySkipsNonIdempotentRequest(t *testing.T) {
	var attempts atomic.Int32
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts.Add(1)
		return responseWith(r, http.StatusServiceUnavailable), nil
	})
	req, _ := http.NewRequest(http.MethodPost, "http://upstream.test/", nil)
	res, err := newFlaky(base, 3).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusServiceUnavailable || attempts.Load() != 1 {
		t.Fatalf("POST was retried: status %d after %d attempts", res.StatusCode, attempts.Load())
	}
}

func TestRetryStopsAtTheAttemptLimit(t *testing.T) {
	var attempts atomic.Int32
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts.Add(1)
		return responseWith(r, http.StatusBadGateway), nil
	})
	req, _ := http.NewRequest(http.MethodGet, "http://upstream.test/", nil)
	res, err := newFlaky(base, 2).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusBadGateway || attempts.Load() != 3 {
		t.Fatalf("got status %d after %d attempts (want 3)", res.StatusCode, attempts.Load())
	}
}

func TestUpstreamErrorStatusSeparatesTimeouts(t *testing.T) {
	if got := upstreamErrorStatus(context.DeadlineExceeded); got != http.StatusGatewayTimeout {
		t.Fatalf("deadline mapped to %d", got)
	}
	var timeout net.Error = timeoutError{}
	if got := upstreamErrorStatus(timeout); got != http.StatusGatewayTimeout {
		t.Fatalf("net timeout mapped to %d", got)
	}
	if got := upstreamErrorStatus(errors.New("connection reset")); got != http.StatusBadGateway {
		t.Fatalf("transport error mapped to %d", got)
	}
}

func TestHeaderOpsApplyInOrder(t *testing.T) {
	h := http.Header{"X-Remove": {"gone"}, "X-Set": {"old"}}
	applyHeaderOps([]model.HeaderOp{
		{Action: "set", Name: "X-Set", Value: "new"},
		{Action: "add", Name: "X-Add", Value: "one"},
		{Action: "add", Name: "X-Add", Value: "two"},
		{Action: "remove", Name: "X-Remove"},
	}, h)
	if h.Get("X-Set") != "new" {
		t.Fatalf("set produced %q", h.Get("X-Set"))
	}
	if len(h.Values("X-Add")) != 2 {
		t.Fatalf("add produced %v", h.Values("X-Add"))
	}
	if h.Get("X-Remove") != "" {
		t.Fatal("remove left the header in place")
	}
}

func TestResponseHeaderOpsReachTheClient(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	base := &http.Transport{}
	req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
	res, err := base.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	applyHeaderOps([]model.HeaderOp{
		{Action: "set", Name: "X-Upstream", Value: "rewritten"},
		{Action: "add", Name: "X-Extra", Value: "1"},
	}, res.Header)
	if res.Header.Get("X-Upstream") != "rewritten" || res.Header.Get("X-Extra") != "1" {
		t.Fatalf("headers not rewritten: %v", res.Header)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func responseWith(req *http.Request, status int) *http.Response {
	return &http.Response{
		StatusCode: status, Status: http.StatusText(status),
		Body: http.NoBody, Header: http.Header{}, Request: req,
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
