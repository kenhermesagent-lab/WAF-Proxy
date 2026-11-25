// Package metrics samples interface counters, conntrack sessions and per-proxy
// request totals for the dashboard.
package metrics

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Iface is one network interface's live counters.
type Iface struct {
	Name  string  `json:"name"`
	RxBps float64 `json:"rx_bps"`
	TxBps float64 `json:"tx_bps"`
	RxPps float64 `json:"rx_pps"`
	TxPps float64 `json:"tx_pps"`
	RxTot uint64  `json:"rx_total"`
	TxTot uint64  `json:"tx_total"`
}

// Point is one second of WAN/LAN history. The proxy fields split the interface
// rate into the proxy's own listeners and everything else on the link.
type Point struct {
	TS      int64   `json:"ts"`
	WANRx   float64 `json:"wan_rx"`
	WANTx   float64 `json:"wan_tx"`
	LANRx   float64 `json:"lan_rx"`
	LANTx   float64 `json:"lan_tx"`
	ProxyRx float64 `json:"proxy_rx"`
	ProxyTx float64 `json:"proxy_tx"`
	HostRx  float64 `json:"host_rx"`
	HostTx  float64 `json:"host_tx"`
}

// Flow is one direction of traffic with the current rate and a running total.
type Flow struct {
	InBps  float64 `json:"in_bps"`
	OutBps float64 `json:"out_bps"`
	InTot  uint64  `json:"in_total"`
	OutTot uint64  `json:"out_total"`
}

// Sessions summarises conntrack state. States is false when only the count was
// readable: Active is still exact, Established and TimeWait are unknown.
type Sessions struct {
	Active      int  `json:"active"`
	Established int  `json:"established"`
	TimeWait    int  `json:"time_wait"`
	Available   bool `json:"available"`
	States      bool `json:"states"`
}

// Counters are per-proxy totals.
type Counters struct {
	Requests int64 `json:"requests"`
	Blocked  int64 `json:"blocked"`
	BytesIn  int64 `json:"bytes_in"`
	BytesOut int64 `json:"bytes_out"`
}

// maxSourcesPerProxy bounds the per-source byte map. A host under a spray of
// addresses keeps its largest contributors instead of growing without limit;
// the bytes of a dropped source stay in the proxy total, which is why an
// unattributed spike is never treated as expected.
const maxSourcesPerProxy = 256

// Load is the host's CPU use, core count and memory.
type Load struct {
	CPUPercent float64 `json:"cpu_percent"`
	Cores      int     `json:"cores"`
	MemUsed    uint64  `json:"mem_used"`
	MemTotal   uint64  `json:"mem_total"`
}

// Snapshot is the payload served to the dashboard.
type Snapshot struct {
	TS       time.Time            `json:"ts"`
	WAN      Iface                `json:"wan"`
	LAN      Iface                `json:"lan"`
	History  []Point              `json:"history"`
	Sessions Sessions             `json:"sessions"`
	Proxies  map[string]*Counters `json:"proxies"`
	DualNIC  bool                 `json:"dual_nic"`
	// Proxy is the traffic the proxy's own listeners moved; Host is the rest
	// of the WAN interface: SSH, the admin console, OS updates and the
	// upstream legs of proxied requests.
	Proxy Flow `json:"proxy"`
	Host  Flow `json:"host"`
	// Request budget of the proxy: what is in flight, what is allowed, and how
	// many requests were refused because the budget was full.
	Inflight    int   `json:"inflight"`
	MaxInflight int   `json:"max_inflight"`
	Shed        int64 `json:"shed"`
	Load        Load  `json:"load"`
}

type ifSample struct {
	rxBytes, txBytes, rxPkts, txPkts uint64
	at                               time.Time
}

// Collector polls the kernel and keeps a one-hour ring buffer.
type Collector struct {
	wanName, lanName string
	mu               sync.RWMutex
	wan, lan         Iface
	history          []Point
	sessions         Sessions
	proxies          map[int64]*Counters
	sources          map[int64]map[string]int64
	last             map[string]ifSample

	wireIn, wireOut atomic.Uint64
	proxy, host     Flow
	lastWire        wireSample

	load    Load
	lastCPU cpuTicks
}

type cpuTicks struct {
	busy, total uint64
}

type wireSample struct {
	in, out uint64
	at      time.Time
	seen    bool
}

// New creates a collector. Empty interface names are auto-detected.
func New(wanName, lanName string) *Collector {
	c := &Collector{
		wanName: wanName,
		lanName: lanName,
		history: make([]Point, 0, 3600),
		proxies: map[int64]*Counters{},
		sources: map[int64]map[string]int64{},
		last:    map[string]ifSample{},
		load:    Load{Cores: runtime.NumCPU()},
	}
	c.autodetect()
	return c
}

func (c *Collector) autodetect() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.detectLocked()
}

// detectLocked fills interface names that were left empty. The caller holds mu.
func (c *Collector) detectLocked() {
	names := listInterfaces()
	if c.wanName == "" {
		// WAN traffic crosses the default-route NIC. Taking the first name
		// from /sys/class/net would pick docker0 on a container host.
		if route := defaultRouteInterface(); route != "" {
			c.wanName = route
		} else if len(names) > 0 {
			c.wanName = names[0]
		}
	}
	if c.lanName == "" {
		for _, n := range names {
			if n != c.wanName {
				c.lanName = n
				break
			}
		}
	}
}

// virtualInterfacePrefixes are container, bridge and test interfaces. Their
// counters describe Docker or VM plumbing rather than the host's own links, so
// auto-detection skips them whenever a physical interface is available.
var virtualInterfacePrefixes = []string{"docker", "veth", "virbr", "dummy", "vnet", "cni", "flannel"}

func isVirtualInterface(name string) bool {
	for _, p := range virtualInterfacePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Interfaces lists the interface names offered as hints in Settings, with
// container and bridge plumbing omitted when a physical link exists.
func Interfaces() []string {
	return listInterfaces()
}

func listInterfaces() []string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	physical := []string{}
	all := []string{}
	for _, e := range entries {
		if e.Name() == "lo" {
			continue
		}
		all = append(all, e.Name())
		if !isVirtualInterface(e.Name()) {
			physical = append(physical, e.Name())
		}
	}
	if len(physical) > 0 {
		return physical
	}
	return all
}

// defaultRouteInterface returns the interface carrying the IPv4 default route,
// or "" when the route table cannot be read (for example on an IPv6-only host).
func defaultRouteInterface() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	return parseDefaultRoute(f)
}

// parseDefaultRoute picks the lowest-metric default route from a
// /proc/net/route table, preferring a physical link over a container bridge.
func parseDefaultRoute(r io.Reader) string {
	sc := bufio.NewScanner(r)
	best, bestMetric := "", int64(0)
	bestVirtual, bestVirtualMetric := "", int64(0)
	for sc.Scan() {
		// Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		metric, err := strconv.ParseInt(fields[6], 10, 64)
		if err != nil {
			metric = 1 << 62
		}
		if isVirtualInterface(fields[0]) {
			if bestVirtual == "" || metric < bestVirtualMetric {
				bestVirtual, bestVirtualMetric = fields[0], metric
			}
			continue
		}
		if best == "" || metric < bestMetric {
			best, bestMetric = fields[0], metric
		}
	}
	if best != "" {
		return best
	}
	return bestVirtual
}

// SetInterfaces updates the sampled interface names. Empty names are
// auto-detected, so clearing a field in Settings does not blank the charts.
func (c *Collector) SetInterfaces(wan, lan string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wanName, c.lanName = wan, lan
	c.detectLocked()
}

// Detected returns the interface names the collector is currently sampling.
func (c *Collector) Detected() (wan, lan string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.wanName, c.lanName
}

// Start samples once per second until the context is cancelled.
func (c *Collector) Start(ctx context.Context) {
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		ct := time.NewTicker(5 * time.Second)
		defer ct.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				c.sample()
			case <-ct.C:
				c.sampleConntrack()
			}
		}
	}()
}

func (c *Collector) sample() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wan = c.readLocked(c.wanName, now)
	c.lan = c.readLocked(c.lanName, now)
	c.splitLocked(now)
	c.loadLocked()
	p := Point{
		TS:    now.Unix(),
		WANRx: c.wan.RxBps, WANTx: c.wan.TxBps,
		LANRx: c.lan.RxBps, LANTx: c.lan.TxBps,
		ProxyRx: c.proxy.InBps, ProxyTx: c.proxy.OutBps,
		HostRx: c.host.InBps, HostTx: c.host.OutBps,
	}
	c.history = append(c.history, p)
	if len(c.history) > 3600 {
		c.history = c.history[len(c.history)-3600:]
	}
}

func (c *Collector) readLocked(name string, now time.Time) Iface {
	out := Iface{Name: name}
	if name == "" {
		return out
	}
	rx, tx, rxp, txp, ok := readInterface(name)
	if !ok {
		return out
	}
	out.RxTot, out.TxTot = rx, tx
	prev, seen := c.last[name]
	if seen {
		dt := now.Sub(prev.at).Seconds()
		if dt > 0 {
			out.RxBps = float64(rx-prev.rxBytes) / dt
			out.TxBps = float64(tx-prev.txBytes) / dt
			out.RxPps = float64(rxp-prev.rxPkts) / dt
			out.TxPps = float64(txp-prev.txPkts) / dt
		}
	}
	c.last[name] = ifSample{rxBytes: rx, txBytes: tx, rxPkts: rxp, txPkts: txp, at: now}
	return out
}

func readInterface(name string) (rx, tx, rxp, txp uint64, ok bool) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, name+":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 10 {
			continue
		}
		rx, _ = strconv.ParseUint(fields[0], 10, 64)
		rxp, _ = strconv.ParseUint(fields[1], 10, 64)
		tx, _ = strconv.ParseUint(fields[8], 10, 64)
		txp, _ = strconv.ParseUint(fields[9], 10, 64)
		return rx, tx, rxp, txp, true
	}
	return 0, 0, 0, 0, false
}

func (c *Collector) sampleConntrack() {
	c.mu.Lock()
	c.sampleConntrackLocked()
	c.mu.Unlock()
}

const (
	conntrackPath      = "/proc/net/nf_conntrack"
	conntrackCountPath = "/proc/sys/net/netfilter/nf_conntrack_count"
)

func (c *Collector) sampleConntrackLocked() {
	if f, err := os.Open(conntrackPath); err == nil {
		defer f.Close()
		c.sessions = parseConntrack(f)
		return
	}
	// The table is root-readable only (0440) while the count is world-readable,
	// so a process that dropped root still reports a live count.
	if n, ok := readConntrackCount(conntrackCountPath); ok {
		c.sessions = Sessions{Active: n, Available: true}
		return
	}
	c.sessions = Sessions{}
}

// parseConntrack counts states in /proc/net/nf_conntrack. The state is the
// token after the timeout; the bracketed ones are flags such as [ASSURED]. A
// stateless protocol (udp, icmp) puts its first attribute in that place.
func parseConntrack(r io.Reader) Sessions {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	s := Sessions{Available: true, States: true}
	lines := 0
	for sc.Scan() {
		lines++
		if lines > 200000 {
			break
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 || strings.ContainsRune(fields[5], '=') {
			continue
		}
		switch fields[5] {
		case "ESTABLISHED":
			s.Established++
		case "TIME_WAIT":
			s.TimeWait++
		}
	}
	s.Active = lines
	return s
}

func readConntrackCount(path string) (int, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// splitLocked divides the WAN interface into proxy and non-proxy traffic. The
// proxy total counts since the service started while the interface total counts
// since boot, so the totals cover different windows; the rates are sampled over
// the same second and are the numbers to compare.
func (c *Collector) splitLocked(now time.Time) {
	in, out := c.wireIn.Load(), c.wireOut.Load()
	p := Flow{InTot: in, OutTot: out}
	if c.lastWire.seen {
		if dt := now.Sub(c.lastWire.at).Seconds(); dt > 0 {
			p.InBps = float64(in-c.lastWire.in) / dt
			p.OutBps = float64(out-c.lastWire.out) / dt
		}
	}
	c.lastWire = wireSample{in: in, out: out, at: now, seen: true}

	c.proxy = p
	c.host = Flow{
		InBps:  nonNegative(c.wan.RxBps - p.InBps),
		OutBps: nonNegative(c.wan.TxBps - p.OutBps),
		InTot:  subtractFloor(c.wan.RxTot, in),
		OutTot: subtractFloor(c.wan.TxTot, out),
	}
}

// loadLocked samples the host's CPU and memory. A one-second CPU window on a
// quiet host flips between 0% and a few percent, which a needle shows as a
// twitch, so the reading is smoothed over the last few frames.
//
// shortcut: /proc reports the whole machine, not a cgroup limit; read
// /sys/fs/cgroup/memory.max and cpu.max when per-container limits matter.
func (c *Collector) loadLocked() {
	if busy, total, ok := readCPU(); ok {
		if total > c.lastCPU.total {
			used := float64(busy-c.lastCPU.busy) / float64(total-c.lastCPU.total) * 100
			c.load.CPUPercent = c.load.CPUPercent*0.5 + used*0.5
		}
		c.lastCPU = cpuTicks{busy: busy, total: total}
	}
	if used, total, ok := readMem(); ok {
		c.load.MemUsed, c.load.MemTotal = used, total
	}
}

func readCPU() (busy, total uint64, ok bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	return parseProcStat(f)
}

// parseProcStat sums the aggregate cpu line. Idle and iowait are time the host
// spent doing nothing, so they count towards the total but not towards busy.
func parseProcStat(r io.Reader) (busy, total uint64, ok bool) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		var t [8]uint64 // user nice system idle iowait irq softirq steal
		for i := range t {
			if i+1 < len(fields) {
				t[i], _ = strconv.ParseUint(fields[i+1], 10, 64)
			}
		}
		busy = t[0] + t[1] + t[2] + t[5] + t[6] + t[7]
		total = busy + t[3] + t[4]
		return busy, total, total > 0
	}
	return 0, 0, false
}

func readMem() (used, total uint64, ok bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	return parseMeminfo(f)
}

// parseMeminfo reports MemTotal against MemAvailable: the gap is what the
// kernel would not hand out, which is what people mean by memory in use.
func parseMeminfo(r io.Reader) (used, total uint64, ok bool) {
	var avail uint64
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = kb * 1024
		case "MemAvailable:":
			avail = kb * 1024
		}
	}
	if total == 0 || avail > total {
		return 0, 0, false
	}
	return total - avail, total, true
}

func nonNegative(v float64) float64 {
	if v < 0 {
		return 0
	}
	return v
}

func subtractFloor(whole, part uint64) uint64 {
	if part > whole {
		return 0
	}
	return whole - part
}

// ProxyBytes reports the bytes the wrapped listeners have moved so far.
func (c *Collector) ProxyBytes() (in, out uint64) {
	if c == nil {
		return 0, 0
	}
	return c.wireIn.Load(), c.wireOut.Load()
}

// CountingListener reports the bytes every accepted connection moves, so the
// dashboard can separate proxy traffic from the host's other WAN traffic. Wrap
// the raw TCP listener, before TLS, to count wire bytes.
func (c *Collector) CountingListener(ln net.Listener) net.Listener {
	if c == nil {
		return ln
	}
	return &countingListener{Listener: ln, c: c}
}

type countingListener struct {
	net.Listener
	c *Collector
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: conn, in: &l.c.wireIn, out: &l.c.wireOut}, nil
}

type countingConn struct {
	net.Conn
	in, out *atomic.Uint64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.in.Add(uint64(n))
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.out.Add(uint64(n))
	}
	return n, err
}

// Count increments per-proxy counters.
func (c *Collector) Count(proxyID int64, requests, blocked, bytesIn, bytesOut int64) {
	c.mu.Lock()
	pc := c.proxies[proxyID]
	if pc == nil {
		pc = &Counters{}
		c.proxies[proxyID] = pc
	}
	c.mu.Unlock()
	if requests != 0 {
		atomic.AddInt64(&pc.Requests, requests)
	}
	if blocked != 0 {
		atomic.AddInt64(&pc.Blocked, blocked)
	}
	if bytesIn != 0 {
		atomic.AddInt64(&pc.BytesIn, bytesIn)
	}
	if bytesOut != 0 {
		atomic.AddInt64(&pc.BytesOut, bytesOut)
	}
}

// CountSource adds one response's outbound bytes to its client, so the detector
// can attribute a window to the sources that moved it. A request that wrote
// nothing is not a source worth remembering.
func (c *Collector) CountSource(proxyID int64, src string, bytesOut int64) {
	if c == nil || proxyID == 0 || src == "" || bytesOut <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	bySrc := c.sources[proxyID]
	if bySrc == nil {
		bySrc = map[string]int64{}
		c.sources[proxyID] = bySrc
	}
	if _, seen := bySrc[src]; !seen && len(bySrc) >= maxSourcesPerProxy {
		evictSource(bySrc)
	}
	bySrc[src] += bytesOut
}

// evictSource drops the smallest contributor, so a flood of distinct addresses
// cannot push out a source that is actually moving traffic.
func evictSource(bySrc map[string]int64) {
	worst, smallest := "", int64(0)
	for addr, n := range bySrc {
		if worst == "" || n < smallest {
			worst, smallest = addr, n
		}
	}
	delete(bySrc, worst)
}

// EgressBySource returns the outbound bytes each client of a proxy has moved so
// far, for the detector's window comparison.
func (c *Collector) EgressBySource(proxyID int64) map[string]int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]int64, len(c.sources[proxyID]))
	for addr, n := range c.sources[proxyID] {
		out[addr] = n
	}
	return out
}

// Snapshot returns the current state for the API.
func (c *Collector) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	hist := make([]Point, len(c.history))
	copy(hist, c.history)
	proxies := map[string]*Counters{}
	for id, pc := range c.proxies {
		cp := &Counters{
			Requests: atomic.LoadInt64(&pc.Requests),
			Blocked:  atomic.LoadInt64(&pc.Blocked),
			BytesIn:  atomic.LoadInt64(&pc.BytesIn),
			BytesOut: atomic.LoadInt64(&pc.BytesOut),
		}
		proxies[strconv.FormatInt(id, 10)] = cp
	}
	return Snapshot{
		TS:       time.Now(),
		WAN:      c.wan,
		LAN:      c.lan,
		History:  hist,
		Sessions: c.sessions,
		Proxies:  proxies,
		DualNIC:  c.wanName != "" && c.lanName != "" && c.wanName != c.lanName,
		Proxy:    c.proxy,
		Host:     c.host,
		Load:     c.load,
	}
}
