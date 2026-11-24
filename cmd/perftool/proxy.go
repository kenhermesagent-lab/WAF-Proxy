package main

// -proxy drives the whole request path instead of the WAF engine alone: a
// proxy.Server with its real listener, event writer and cache, in front of stub
// upstreams. Capacity claims in docs/BENCHMARKS.md come from here, so they name
// the host and the date they were measured on.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/botguard"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/gate"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/policy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/proxy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

type proxyConfig struct {
	Root     string
	Duration time.Duration
	Clients  int
	Hosts    int
	Body     int
	Cache    bool
	// CacheFirst sets the per-site cache_pre_waf setting, so a hit is answered
	// before the CRS.
	CacheFirst bool
	// Encoding asks the proxy for a compressed body, which is what a cached
	// hit serves.
	Encoding string
	HTTP2    bool
	WAF      bool
	Record   bool
	// Inflight and Queue override the admission budget, so a run can show what
	// the old immediate-shed behaviour did on the same host.
	Inflight int
	Queue    time.Duration
}

// proxyResult is the file written per mode. Every field is a measurement, not
// an estimate; a field the run could not measure stays zero.
type proxyResult struct {
	Recorded     string  `json:"recorded"`
	Host         string  `json:"host"`
	Go           string  `json:"go"`
	Mode         string  `json:"mode"`
	Proto        string  `json:"proto"`
	WAF          string  `json:"waf"`
	Clients      int     `json:"clients"`
	Hosts        int     `json:"hosts"`
	Budget       int     `json:"budget"`
	QueueMS      int     `json:"queue_ms"`
	BodyBytes    int     `json:"body_bytes"`
	Seconds      float64 `json:"seconds"`
	Requests     int64   `json:"requests"`
	RPS          float64 `json:"rps"`
	P50MS        float64 `json:"p50_ms"`
	P95MS        float64 `json:"p95_ms"`
	P99MS        float64 `json:"p99_ms"`
	BytesOut     int64   `json:"bytes_out"`
	Shed         int64   `json:"shed"`
	Errors       int64   `json:"errors"`
	PeakRSSBytes int64   `json:"peak_rss_bytes"`
}

func (c proxyConfig) mode() string {
	m := "cache-off"
	if c.Cache {
		m = "cache-on"
	}
	if c.Encoding != "" && c.Encoding != "off" {
		m += "-" + c.Encoding
	}
	if c.CacheFirst {
		m += "-cachefirst"
	}
	if c.HTTP2 {
		m += "-h2"
	}
	if c.WAF {
		m += "-waf"
	}
	if c.Inflight > 0 {
		m += fmt.Sprintf("-budget%d", c.Inflight)
	}
	if c.Queue == 0 {
		m += "-queue0"
	}
	return m
}

// runProxy is the -proxy entry point: measure, print, then write or compare.
func runProxy(c proxyConfig) int {
	res, err := proxyRun(c)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("proxy %s (%s, waf %s): %d clients, %d hosts, %d B body, budget %d, queue %d ms\n",
		res.Mode, res.Proto, res.WAF, res.Clients, res.Hosts, res.BodyBytes, res.Budget, res.QueueMS)
	fmt.Printf("%d requests in %.1fs: %.0f rps, %.1f MiB/s out\n",
		res.Requests, res.Seconds, res.RPS, float64(res.BytesOut)/res.Seconds/(1<<20))
	fmt.Printf("latency p50 %.2fms  p95 %.2fms  p99 %.2fms  shed %d  errors %d  peak RSS %.1f MiB\n",
		res.P50MS, res.P95MS, res.P99MS, res.Shed, res.Errors, float64(res.PeakRSSBytes)/(1<<20))

	path := filepath.Join(c.Root, "perf", "proxy-"+res.Mode+".json")
	if c.Record {
		if err := writeProxyResult(path, res); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("recorded %s\n", path)
		return 0
	}
	prev, err := readProxyResult(path)
	if err != nil {
		fmt.Printf("no recorded baseline at %s; run with -record to write one\n", path)
		return 0
	}
	fmt.Printf("versus %s: rps %+.1f%%, p95 %+.1f%%, peak RSS %+.1f%%\n", path,
		percent(prev.RPS, res.RPS), percent(prev.P95MS, res.P95MS),
		percent(float64(prev.PeakRSSBytes), float64(res.PeakRSSBytes)))
	return 0
}

func percent(before, now float64) float64 {
	if before == 0 {
		return 0
	}
	return (now - before) / before * 100
}

func readProxyResult(path string) (proxyResult, error) {
	var r proxyResult
	data, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(data, &r)
	return r, err
}

func writeProxyResult(path string, r proxyResult) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// proxyRun builds a throwaway installation, loops a keep-alive client fan-out
// over it and reports what the pipeline did. The directory, store and listeners
// are released before it returns.
func proxyRun(c proxyConfig) (proxyResult, error) {
	if c.Clients <= 0 {
		c.Clients = 200
	}
	if c.Hosts <= 0 {
		c.Hosts = 4
	}
	if c.Body <= 0 {
		c.Body = 1024
	}
	if c.Duration <= 0 {
		c.Duration = 30 * time.Second
	}

	dir, err := os.MkdirTemp("", "perftool-proxy")
	if err != nil {
		return proxyResult{}, err
	}
	defer os.RemoveAll(dir)
	st, err := store.Open(dir)
	if err != nil {
		return proxyResult{}, err
	}
	defer st.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	box, err := wfcrypto.New(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		return proxyResult{}, err
	}
	bans, err := ban.New(st, log, nil)
	if err != nil {
		return proxyResult{}, err
	}
	geo := geoip.Open(dir)
	// Every client shares one loopback source, so the policy engine's default
	// 100 rps per source would measure the rate limiter instead of the pipeline.
	settings := map[string]string{"dos_rps": "1000000", "dos_burst": "1000000"}
	if c.CacheFirst {
		settings["cache_pre_waf"] = "1"
	}
	if err := st.SetSettings(settings); err != nil {
		return proxyResult{}, err
	}
	profiles, err := st.ListProfiles()
	if err != nil {
		return proxyResult{}, err
	}
	wafs := waf.NewSet(profiles, log)
	pol, err := policy.New(st, bans, nil, geo, wafs, log)
	if err != nil {
		return proxyResult{}, err
	}

	body := proxyAsset(c.Body)
	cacheControl := "no-store"
	if c.Cache {
		cacheControl = "max-age=60"
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The health probe is not a client request.
		if r.Header.Get("User-Agent") == "wafproxy-health/1.0" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", cacheControl)
		_, _ = w.Write(body)
	}))
	defer upstream.Close()

	var wafProfile int64
	if c.WAF {
		for _, p := range profiles {
			if p.Name == "Generic Web" {
				wafProfile = p.ID
			}
		}
		if wafProfile == 0 {
			return proxyResult{}, fmt.Errorf("the Generic Web profile is missing, so -waf cannot be measured")
		}
	}

	hosts := make([]string, c.Hosts)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("site%d.test", i)
		p := model.Proxy{Hostname: hosts[i], Enabled: true, GateMode: "off", Fingerprint: "strict",
			BotLevel: "off", WAFMode: "off"}
		if c.WAF {
			p.WAFMode, p.ProfileID = "block", &wafProfile
		}
		id, err := st.CreateProxy(&p)
		if err != nil {
			return proxyResult{}, err
		}
		if err := st.ReplaceUpstreams(id, []model.Upstream{{ProxyID: id, URL: upstream.URL, Weight: 1, Enabled: true}}); err != nil {
			return proxyResult{}, err
		}
	}

	px, err := proxy.New(proxy.Deps{
		Store: st, Policy: pol, Gate: gate.New(st, box, bans, log),
		Bots: botguard.New(bytes.Repeat([]byte{0x42}, 32), bans, st, log),
		Bans: bans, Geo: geo, Metrics: metrics.New("", ""), Log: log,
	})
	if err != nil {
		return proxyResult{}, err
	}
	// The run measures the pipeline unless a budget is set: twice the client
	// count leaves the queue idle so a shed here is a real finding.
	budget := c.Inflight
	if budget <= 0 {
		budget = c.Clients * 2
	}
	px.SetMaxInflight(budget)
	px.SetBudget(proxy.DefaultMaxBufferedBytes, c.Queue)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := px.Reload(ctx); err != nil {
		return proxyResult{}, err
	}

	// ListenWith takes a binder, so the harness knows the port the real
	// listener and its event writer are serving on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return proxyResult{}, err
	}
	lns, err := px.ListenWith(ctx, func(string) (net.Listener, error) { return ln, nil }, "127.0.0.1:0")
	if err != nil {
		return proxyResult{}, err
	}
	go func() { _ = lns.Serve() }()
	defer lns.Close()
	addr := ln.Addr().String()

	// One client per host: the SNI name and the Host header must both name the
	// site, and a shared transport could not offer two different names.
	perHost := c.Clients / len(hosts)
	if perHost < 1 {
		perHost = 1
	}
	clients := make([]*http.Client, len(hosts))
	for i, h := range hosts {
		tc := &tls.Config{ServerName: h, InsecureSkipVerify: true}
		if !c.HTTP2 {
			tc.NextProtos = []string{"http/1.1"}
		}
		tr := &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:        c.Clients,
			MaxIdleConnsPerHost: perHost,
			IdleConnTimeout:     90 * time.Second,
			ForceAttemptHTTP2:   c.HTTP2,
			TLSClientConfig:     tc,
		}
		clients[i] = &http.Client{Transport: tr, Timeout: 60 * time.Second}
	}
	defer func() {
		for _, cl := range clients {
			cl.CloseIdleConnections()
		}
	}()

	accept := ""
	switch c.Encoding {
	case "", "off":
	case "br":
		accept = "gzip, deflate, br"
	case "gzip":
		accept = "gzip"
	default:
		return proxyResult{}, fmt.Errorf("-encoding %q: want off, br or gzip", c.Encoding)
	}

	url := "https://" + addr + "/asset"
	deadline := time.Now().Add(c.Duration)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var requests, errorsSeen, bytesOut atomic.Int64
	samples := make([]time.Duration, 0, 1<<16)
	start := time.Now()
	for w := 0; w < c.Clients; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			host := hosts[w%len(hosts)]
			client := clients[w%len(hosts)]
			local := make([]time.Duration, 0, 4096)
			for time.Now().Before(deadline) {
				req, err := http.NewRequest(http.MethodGet, url, nil)
				if err != nil {
					errorsSeen.Add(1)
					continue
				}
				req.Host = host
				if accept != "" {
					req.Header.Set("Accept-Encoding", accept)
				}
				began := time.Now()
				res, err := client.Do(req)
				if err != nil {
					errorsSeen.Add(1)
					continue
				}
				n, cerr := io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
				if cerr != nil || res.StatusCode != http.StatusOK {
					errorsSeen.Add(1)
					continue
				}
				bytesOut.Add(n)
				requests.Add(1)
				local = append(local, time.Since(began))
			}
			mu.Lock()
			samples = append(samples, local...)
			mu.Unlock()
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)

	_, _, shed := px.Capacity()
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	pct := func(q float64) float64 {
		if len(samples) == 0 {
			return 0
		}
		i := int(float64(len(samples)) * q)
		if i >= len(samples) {
			i = len(samples) - 1
		}
		return float64(samples[i].Microseconds()) / 1000
	}
	proto := "h1"
	if c.HTTP2 {
		proto = "h2"
	}
	wafMode := "off"
	if c.WAF {
		wafMode = "block"
	}
	total := requests.Load()
	return proxyResult{
		Recorded:     time.Now().UTC().Format("2006-01-02"),
		Host:         cpuModel(),
		Go:           runtime.Version(),
		Mode:         c.mode(),
		Proto:        proto,
		WAF:          wafMode,
		Clients:      c.Clients,
		Hosts:        len(hosts),
		Budget:       budget,
		QueueMS:      int(c.Queue / time.Millisecond),
		BodyBytes:    len(body),
		Seconds:      elapsed.Seconds(),
		Requests:     total,
		RPS:          float64(total) / elapsed.Seconds(),
		P50MS:        pct(0.50),
		P95MS:        pct(0.95),
		P99MS:        pct(0.99),
		BytesOut:     bytesOut.Load(),
		Shed:         shed,
		Errors:       errorsSeen.Load(),
		PeakRSSBytes: peakRSS(),
	}, nil
}

// proxyAsset builds a body shaped like a page a site serves: repeated markup
// with varying numbers, so compression weighs what it weighs on real HTML
// instead of the near-zero bytes a repeated string produces.
func proxyAsset(n int) []byte {
	var b bytes.Buffer
	for b.Len() < n {
		i := b.Len()
		fmt.Fprintf(&b, "<div class=\"row row-%d\" data-id=\"%d\"><span>cached asset %d</span></div>\n", i, i*7919%100000, i*104729%100000)
	}
	return b.Bytes()[:n]
}

// cpuModel names the machine the numbers belong to.
func cpuModel() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return runtime.GOOS + "/" + runtime.GOARCH
	}
	for _, line := range strings.Split(string(data), "\n") {
		if name, ok := strings.CutPrefix(line, "model name"); ok {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(name), ":"))
		}
	}
	return runtime.GOOS + "/" + runtime.GOARCH
}

// peakRSS reads the process high-water mark, which is the memory a burst
// actually asked the kernel for.
func peakRSS() int64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "VmHWM:"); ok {
			fields := strings.Fields(rest)
			if len(fields) == 0 {
				return 0
			}
			kb, err := strconv.ParseInt(fields[0], 10, 64)
			if err != nil {
				return 0
			}
			return kb * 1024
		}
	}
	return 0
}
