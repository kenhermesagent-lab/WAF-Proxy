// Package canary probes a deployed site end to end and names the stage that
// failed, so an operator sees whether DNS, TLS, routing, the WAF or the upstream
// is at fault instead of a single timeout.
package canary

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Path is the benign URL the probe requests. It matches no rule and no route,
// so a WAF block or an upstream error is visible as such.
const Path = "/.well-known/wafproxy-canary"

// Stage is one step of the probe.
type Stage struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Result is a completed probe. Failed names the first stage that did not pass.
type Result struct {
	OK     bool    `json:"ok"`
	Host   string  `json:"host"`
	URL    string  `json:"url"`
	Failed string  `json:"failed_stage,omitempty"`
	Stages []Stage `json:"stages"`
}

// Probe runs one check against a host.
type Probe interface {
	Run(ctx context.Context, host string) Result
}

// Prober carries the dialers and client so tests can replace the network.
type Prober struct {
	Client *http.Client
	Dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	Now    func() time.Time
	// Scheme defaults to https; tests use http for a plain listener.
	Scheme string
}

func (p Prober) client() *http.Client {
	if p.Client != nil {
		return p.Client
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			DialContext:     p.Dial,
		},
	}
}

func (p Prober) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Run probes one hostname and stops recording once a stage fails. Later stages
// are reported as skipped so the list stays in pipeline order.
func (p Prober) Run(ctx context.Context, host string) Result {
	host = strings.ToLower(strings.TrimSpace(host))
	scheme := p.Scheme
	if scheme == "" {
		scheme = "https"
	}
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	res := Result{Host: host, URL: scheme + "://" + host + Path}
	add := func(name string, ok bool, detail string) bool {
		res.Stages = append(res.Stages, Stage{Name: name, OK: ok, Detail: detail})
		if !ok && res.Failed == "" {
			res.Failed = name
		}
		return ok
	}
	if !add("config", name != "" && !strings.ContainsAny(name, " /"), "hostname") {
		return res
	}
	ips, err := net.DefaultResolver.LookupHost(ctx, name)
	if err != nil {
		add("dns", false, err.Error())
		return res
	}
	add("dns", true, strings.Join(ips, ","))

	start := p.now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, res.URL, nil)
	if err != nil {
		add("request", false, err.Error())
		return res
	}
	req.Host = name
	req.Header.Set("User-Agent", "WAF-Proxy-Canary/1")
	resp, err := p.client().Do(req)
	if err != nil {
		add("connect", false, err.Error())
		return res
	}
	defer resp.Body.Close()
	add("connect", true, p.now().Sub(start).Round(time.Millisecond).String())

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	switch {
	case resp.StatusCode == http.StatusForbidden:
		add("waf", false, "the WAF blocked the canary with 403")
	case resp.StatusCode == http.StatusTooManyRequests:
		add("waf", false, "the WAF rate-limited the canary with 429")
	case resp.StatusCode == http.StatusMisdirectedRequest:
		add("route", false, "the host was routed away from its site")
	case resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable:
		add("upstream", false, fmt.Sprintf("upstream answered %d", resp.StatusCode))
	case resp.StatusCode >= 500:
		add("upstream", false, fmt.Sprintf("upstream answered %d", resp.StatusCode))
	default:
		add("route", true, resp.Header.Get("X-Waf-Proxy-Route"))
		add("waf", true, fmt.Sprintf("status %d", resp.StatusCode))
		add("upstream", true, fmt.Sprintf("%d bytes", len(body)))
	}
	if res.Failed == "" {
		res.OK = true
	}
	return res
}
