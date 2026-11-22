package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// retryTransport retries idempotent requests that fail before any response is
// read, and upstream 502/503/504 answers. Because the decision lives inside
// RoundTrip, no byte has been written to the client yet.
type retryTransport struct {
	base    http.RoundTripper
	retries int
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	attempts := t.retries + 1
	var lastResp *http.Response
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(time.Duration(attempt) * 50 * time.Millisecond):
			}
		}
		out, err := t.roundTripOnce(req)
		if err != nil {
			lastErr, lastResp = err, nil
			if !retryableRequest(req) || !retryableError(err) {
				return nil, err
			}
			continue
		}
		if !retryableRequest(req) || out.StatusCode < 502 || out.StatusCode > 504 {
			return out, nil
		}
		lastResp, lastErr = out, nil
		if attempt == attempts-1 {
			break
		}
		// Buffered request bodies can be replayed; a streamed body cannot, so
		// the response is handed back rather than losing the body.
		if req.Body != nil && req.GetBody == nil {
			return out, nil
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(out.Body, 4<<10))
		_ = out.Body.Close()
	}
	if lastResp != nil {
		return lastResp, nil
	}
	return nil, lastErr
}

func (t *retryTransport) roundTripOnce(req *http.Request) (*http.Response, error) {
	if req.Body == nil || req.GetBody == nil {
		return t.base.RoundTrip(req)
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	clone := req.Clone(req.Context())
	clone.Body = body
	return t.base.RoundTrip(clone)
}

// retryableRequest limits retries to methods where a repeat is safe.
func retryableRequest(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPut, http.MethodDelete:
		return true
	}
	return false
}

func retryableError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return true
}

// upstreamErrorStatus maps a forwarding failure to 504 for a timeout and 502
// for everything else, so an operator can tell "slow" from "broken".
func upstreamErrorStatus(err error) int {
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

// applyHeaderOps rewrites a header set with the configured rules, in order.
func applyHeaderOps(ops []model.HeaderOp, h http.Header) {
	for _, op := range ops {
		name := strings.TrimSpace(op.Name)
		if name == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(op.Action)) {
		case "set":
			h.Set(name, op.Value)
		case "add":
			h.Add(name, op.Value)
		case "remove":
			h.Del(name)
		}
	}
}
