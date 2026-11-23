// Command perftool measures the WAF hot path. With no flags it compares the
// benchmarks in this repository against perf/baseline.json and fails when one
// is more than the tolerance slower or allocates more. -record rewrites the
// baseline; -load replays the request mix for a duration and prints latency
// percentiles; -proxy drives the whole pipeline against stub upstreams and
// writes perf/proxy-<mode>.json.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/perf"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

type sample struct {
	NsPerOp  float64 `json:"ns_op"`
	AllocsOp float64 `json:"allocs_op"`
}

type baseline struct {
	Recorded  string `json:"recorded"`
	GoVersion string `json:"go"`
	// Allocations are deterministic for the same code, so they are gated
	// tightly. Wall time on a shared runner swings by tens of percent between
	// identical runs, so it only guards against an order-of-magnitude change;
	// 'make perf' is the number to quote.
	AllocsTolerance float64           `json:"allocs_tolerance"`
	TimeTolerance   float64           `json:"time_tolerance"`
	Benchmarks      map[string]sample `json:"benchmarks"`
}

const benchPattern = "BenchmarkInspectBenign|BenchmarkInspectSQLi|BenchmarkMix"

var benchLine = regexp.MustCompile(`^(\w+)(?:-\d+)?\s+\d+\s+([0-9.]+) ns/op\s+([0-9.]+) B/op\s+([0-9.]+) allocs/op`)

func main() {
	dir := flag.String("dir", ".", "repository root to run the benchmarks in")
	path := flag.String("baseline", "perf/baseline.json", "baseline file")
	benchtime := flag.String("benchtime", "500x", "go test -benchtime")
	record := flag.Bool("record", false, "rewrite the baseline from this machine")
	loadFor := flag.Duration("load", 0, "replay the request mix for this long (for example 5s) instead of gating")
	workers := flag.Int("workers", runtime.NumCPU(), "load workers")
	proxyMode := flag.Bool("proxy", false, "drive the whole proxy pipeline against stub upstreams instead of gating")
	duration := flag.Duration("duration", 30*time.Second, "-proxy: load duration")
	clients := flag.Int("clients", 200, "-proxy: concurrent keep-alive clients")
	sites := flag.Int("sites", 4, "-proxy: hostnames behind the proxy")
	body := flag.Int("body", 1024, "-proxy: upstream response size in bytes")
	cache := flag.String("cache", "off", "-proxy: off or on (let the upstream response be cacheable)")
	h2 := flag.Bool("h2", false, "-proxy: speak HTTP/2 between client and proxy")
	wafMode := flag.String("waf", "off", "-proxy: off or block (the Generic Web profile)")
	inflight := flag.Int("inflight", 0, "-proxy: request budget (default twice the client count)")
	queue := flag.Duration("queue", 250*time.Millisecond, "-proxy: how long a request waits for budget; 0 refuses at once")
	flag.Parse()

	if *proxyMode {
		cacheOn, err := onOff("-cache", *cache)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		var wafOn bool
		switch strings.ToLower(strings.TrimSpace(*wafMode)) {
		case "block", "on":
			wafOn = true
		case "off":
			wafOn = false
		default:
			fmt.Fprintf(os.Stderr, "-waf: %q is not off or block\n", *wafMode)
			os.Exit(1)
		}
		os.Exit(runProxy(proxyConfig{Root: *dir, Duration: *duration, Clients: *clients,
			Hosts: *sites, Body: *body, Cache: cacheOn, HTTP2: *h2, WAF: wafOn, Record: *record,
			Inflight: *inflight, Queue: *queue}))
	}
	if *loadFor > 0 {
		os.Exit(runLoad(*loadFor, *workers))
	}
	got, err := runBench(*dir, *benchtime)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *record {
		os.Exit(writeBaseline(*path, got))
	}
	os.Exit(check(*path, got))
}

func runBench(dir, benchtime string) (map[string]sample, error) {
	cmd := exec.Command("go", "test", "-run", "^$", "-bench", benchPattern,
		"-benchmem", "-count=1", "-benchtime", benchtime, "./internal/waf", "./internal/perf")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("go test -bench failed: %v\n%s", err, out)
	}
	got := map[string]sample{}
	for _, line := range strings.Split(string(out), "\n") {
		m := benchLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		ns, _ := strconv.ParseFloat(m[2], 64)
		allocs, _ := strconv.ParseFloat(m[4], 64)
		got[m[1]] = sample{NsPerOp: ns, AllocsOp: allocs}
	}
	if len(got) == 0 {
		return nil, fmt.Errorf("no benchmark results in output:\n%s", out)
	}
	return got, nil
}

func readBaseline(path string) (baseline, error) {
	var b baseline
	data, err := os.ReadFile(path)
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return b, fmt.Errorf("%s: %v", path, err)
	}
	return b, nil
}

func writeBaseline(path string, got map[string]sample) int {
	b := baseline{
		Recorded:        time.Now().UTC().Format("2006-01-02"),
		GoVersion:       runtime.Version(),
		AllocsTolerance: 0.25,
		TimeTolerance:   2.0,
		Benchmarks:      got,
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("recorded %d benchmarks in %s\n", len(got), path)
	return 0
}

// check fails when a benchmark grew past the tolerance. A benchmark present in
// the baseline but missing from the run also fails: a benchmark that stopped
// running cannot demonstrate anything.
func check(path string, got map[string]sample) int {
	base, err := readBaseline(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read baseline: %v\nrun 'make perf-record' on this machine class\n", err)
		return 1
	}
	allocsTol := base.AllocsTolerance
	if allocsTol <= 0 {
		allocsTol = 0.25
	}
	timeTol := base.TimeTolerance
	if timeTol <= 0 {
		timeTol = 2.0
	}
	names := make([]string, 0, len(base.Benchmarks))
	for name := range base.Benchmarks {
		names = append(names, name)
	}
	sort.Strings(names)
	failed := false
	fmt.Printf("%-26s %12s %12s %8s %8s\n", "benchmark", "ns/op", "baseline", "allocs", "base")
	for _, name := range names {
		want := base.Benchmarks[name]
		have, ok := got[name]
		if !ok {
			fmt.Printf("%-26s  missing from this run\n", name)
			failed = true
			continue
		}
		// Bytes per request move with the payload, so only time and allocations
		// are gated; a regression there always shows in one of the two.
		slow := have.NsPerOp > want.NsPerOp*(1+timeTol)
		fat := have.AllocsOp > want.AllocsOp*(1+allocsTol)
		mark := ""
		if slow || fat {
			mark = "  REGRESSION"
			failed = true
		}
		fmt.Printf("%-26s %12.0f %12.0f %8.0f %8.0f%s\n", name, have.NsPerOp, want.NsPerOp, have.AllocsOp, want.AllocsOp, mark)
	}
	if failed {
		fmt.Fprintf(os.Stderr, "\nperformance gate failed (allocations +%.0f%%, time +%.0f%%).\n"+
			"If this runner class is new, re-record with 'make perf-record' and review the diff.\n",
			allocsTol*100, timeTol*100)
		return 1
	}
	fmt.Printf("\nperformance gate passed (allocations +%.0f%%, time +%.0f%%)\n", allocsTol*100, timeTol*100)
	return 0
}

// onOff reads an on/off flag value, so a run states its mode instead of
// relying on a bare boolean whose default a reader has to look up.
func onOff(name, v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "yes", "true", "1":
		return true, nil
	case "off", "no", "false", "0":
		return false, nil
	}
	return false, fmt.Errorf("%s: %q is not on or off", name, v)
}

func runLoad(d time.Duration, workers int) int {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	set := waf.NewSet([]model.Profile{{ID: 1, Name: "load", Mode: "block", Paranoia: 1, Anomaly: 5, MaxBody: 131072}}, log)
	id := int64(1)
	engine := set.For(&id)
	if engine == nil {
		fmt.Fprintln(os.Stderr, "WAF engine unavailable")
		return 1
	}
	cases := perf.Mix()
	requests := make([]*http.Request, len(cases))
	bodies := make([][]byte, len(cases))
	for i, c := range cases {
		r, err := http.NewRequest(c.Method, "https://app.example.com"+c.Target, strings.NewReader(c.Body))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		r.Header.Set("User-Agent", c.UA)
		if c.Type != "" {
			r.Header.Set("Content-Type", c.Type)
		}
		requests[i], bodies[i] = r, []byte(c.Body)
	}
	addr := netip.MustParseAddr("198.51.100.20")

	// Bodies are read-only here, so every worker shares the requests instead of
	// building its own copy.
	deadline := time.Now().Add(d)
	var mu sync.Mutex
	var samples []time.Duration
	var total int64
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			local := make([]time.Duration, 0, 4096)
			var n int
			for i := w; time.Now().Before(deadline); i++ {
				j := i % len(cases)
				began := time.Now()
				engine.Inspect(requests[j], bodies[j], addr)
				local = append(local, time.Since(began))
				n++
			}
			mu.Lock()
			samples = append(samples, local...)
			total += int64(n)
			mu.Unlock()
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	pct := func(q float64) time.Duration {
		if len(samples) == 0 {
			return 0
		}
		i := int(float64(len(samples)) * q)
		if i >= len(samples) {
			i = len(samples) - 1
		}
		return samples[i]
	}
	fmt.Printf("load %s, %d workers: %d requests, %.0f rps\n", elapsed.Round(time.Millisecond), workers,
		total, float64(total)/elapsed.Seconds())
	fmt.Printf("latency p50 %s  p95 %s  p99 %s\n", pct(0.50), pct(0.95), pct(0.99))
	return 0
}
