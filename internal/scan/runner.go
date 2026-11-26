package scan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/gate"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/scantrust"
)

// ErrAborted is returned when the published path refused the scanner often
// enough that carrying on would only deepen a rate limit or a ban.
var ErrAborted = errors.New("scan aborted: the published path kept refusing")

const (
	maxRefusals    = 5
	probeTimeout   = 5 * time.Second
	maxAnswerBytes = 256 << 10
	scanUserAgent  = "wafproxy-scan/1.0"
	// probeTagHeader names the probe in the request log, so a rule that fired
	// can be traced back to the request that triggered it.
	probeTagHeader = "X-Scan-Probe"
)

// Runner sends probes through the published path and straight to the upstream.
type Runner struct {
	wan, upstream       Endpoint
	wanClient, upClient *http.Client
	perSecond           int
	last                time.Time
	// RunID tags every request for the request log. Zero leaves it untagged,
	// which a preflight-only caller may do.
	RunID int64
	// Token marks every probe as this run's. The policy trusts it only while
	// the registry holds it, so no other client can borrow the exemption.
	Token string

	mu      sync.Mutex
	sources map[string]struct{}
}

// NewRunner builds a runner for one target. perSecond paces the probes; zero
// sends them as fast as the target answers, which tests use.
func NewRunner(wan, upstream Endpoint, perSecond int) *Runner {
	return &Runner{
		wan:       wan,
		upstream:  upstream,
		wanClient: probeClient(false, wan.TLSName),
		upClient:  probeClient(upstream.Insecure, upstream.TLSName),
		perSecond: perSecond,
		sources:   map[string]struct{}{},
	}
}

func probeClient(insecure bool, tlsName string) *http.Client {
	return &http.Client{
		Timeout: probeTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure, ServerName: tlsName},
		},
		// A redirect is part of the answer: following it would hide the gate.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Run sends every probe and returns one evidence row per probe. It stops early
// when the published path keeps refusing, returning the rows so far.
func (r *Runner) Run(ctx context.Context, probes []Probe) ([]model.ScanEvidence, error) {
	out := make([]model.ScanEvidence, 0, len(probes))
	refused := map[string]bool{}
	failures := 0
	for i, p := range probes {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if p.Skip != "" {
			out = append(out, r.row(i, p, string(NotRun), p.Skip))
			continue
		}
		if refused[p.Class] {
			out = append(out, r.row(i, p, string(NotRun), skipControl))
			continue
		}
		if !allowedMethod(p.Method, p.Path) {
			out = append(out, r.row(i, p, string(NotRun), "method not allowed"))
			continue
		}
		r.pace()
		ev := r.probe(ctx, i, p)
		if p.Control && (ev.Verdict == string(BlockedWAF) || ev.Verdict == string(BlockedGate)) {
			// The control was refused too, so a refusal of the payloads cannot
			// be told apart from a blanket rule. Stop sending the class.
			refused[p.Class] = true
			ev.Verdict = string(Inconclusive)
			ev.Note = "the control request was refused too"
		}
		out = append(out, ev)
		if wanRefusal(ev.WANStatus) {
			failures++
			if failures >= maxRefusals {
				return out, ErrAborted
			}
			continue
		}
		failures = 0
	}
	return out, nil
}

// unreachableNote names the endpoint actually dialled and why it failed. A
// bare "did not answer" hides whether the port, the address or TLS was wrong.
func (r *Runner) unreachableNote(which string, ep Endpoint, err error) string {
	return "the " + which + " endpoint " + ep.Label() + " did not answer: " + shortError(err)
}

// row builds an evidence row for a probe that was not sent.
func (r *Runner) row(seq int, p Probe, verdict, note string) model.ScanEvidence {
	return model.ScanEvidence{
		Seq: seq, Stage: p.Stage, Class: p.Class, Method: p.Method, Path: p.Path,
		Verdict: verdict, Note: note, Detail: RedactRequest(p),
	}
}

// probe sends one request through both paths and compares the answers. A
// WAN-only probe is compared with nothing; a gate-login POST never reaches the
// application.
func (r *Runner) probe(ctx context.Context, seq int, p Probe) model.ScanEvidence {
	p = r.tagProbe(p, seq)
	ev := model.ScanEvidence{
		Seq: seq, Stage: p.Stage, Class: p.Class, Method: p.Method, Path: p.Path,
		Detail: RedactRequest(p),
	}
	var wan answer
	var err error
	if p.Raw != "" {
		wan, err = r.sendRaw(ctx, p.Raw)
	} else {
		wan, err = r.send(ctx, r.wanClient, r.wan, p)
	}
	if err != nil {
		ev.Verdict = string(NotRun)
		ev.Note = r.unreachableNote("published", r.wan, err)
		return ev
	}
	ev.WANStatus = wan.status
	ev.WANHash = wan.hash()

	if p.WANOnly {
		if wanRefusal(wan.status) {
			ev.Verdict = string(BlockedWAF)
		} else {
			ev.Verdict = string(NotBlocked)
		}
		ev.Note = joinNote(p.Note, "the upstream half was skipped")
		return ev
	}

	if p.Method == http.MethodPost && p.Path == gate.LoginPath {
		// The gate login is the only POST that must never reach the app.
		if isGatePage(wan) || wan.status == http.StatusSeeOther {
			ev.Verdict = string(BlockedGate)
		} else {
			ev.Verdict = string(Inconclusive)
			ev.Note = "the gate answered something else"
		}
		return ev
	}

	up, err := r.send(ctx, r.upClient, r.upstream, p)
	if err != nil {
		ev.Verdict = string(Inconclusive)
		ev.Note = r.unreachableNote("upstream", r.upstream, err)
		return ev
	}
	v, sim := verdictFor(wan, up)
	if v == Inconclusive {
		// One retry separates a dynamic page from a real difference.
		wan, up = r.retry(ctx, p, wan, up)
		v, sim = verdictFor(wan, up)
	}
	ev.Verdict = string(v)
	ev.UpStatus = up.status
	ev.UpHash = up.hash()
	ev.Similarity = sim
	if v == Inconclusive {
		ev.Note = "the two answers could not be compared"
	}
	return ev
}

func (r *Runner) retry(ctx context.Context, p Probe, wan, up answer) (answer, answer) {
	if again, err := r.send(ctx, r.wanClient, r.wan, p); err == nil {
		wan = again
	}
	if again, err := r.send(ctx, r.upClient, r.upstream, p); err == nil {
		up = again
	}
	return wan, up
}

func (r *Runner) send(ctx context.Context, c *http.Client, ep Endpoint, p Probe) (answer, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { r.noteSource(info.Conn.LocalAddr()) },
	})

	u := *ep.URL
	u.Path = strings.TrimSuffix(u.Path, "/") + p.Path
	u.RawQuery = p.Query
	req, err := http.NewRequestWithContext(ctx, p.Method, u.String(), strings.NewReader(p.Body))
	if err != nil {
		return answer{}, err
	}
	req.Host = ep.Host
	if p.HostOverride != "" {
		req.Host = p.HostOverride
	}
	for name, values := range p.Header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	if r.Token != "" {
		req.Header.Set(scantrust.Header, r.Token)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", scanUserAgent)
	}

	resp, err := c.Do(req)
	if err != nil {
		return answer{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes))
	if err != nil {
		return answer{}, err
	}
	return answer{status: resp.StatusCode, header: resp.Header.Clone(), body: body}, nil
}

// tagProbe marks the request so the request log can name it.
func (r *Runner) tagProbe(p Probe, seq int) Probe {
	if r.RunID == 0 {
		return p
	}
	header := http.Header{}
	for name, values := range p.Header {
		header[name] = append([]string(nil), values...)
	}
	header.Set(probeTagHeader, fmt.Sprintf("%d-%d", r.RunID, seq))
	p.Header = header
	return p
}

// noteSource remembers an address a probe left from, which is what makes a
// run's leftover bans findable.
func (r *Runner) noteSource(addr net.Addr) {
	if addr == nil {
		return
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sources[host] = struct{}{}
}

// Sources lists the addresses the probes left from, as the kernel chose them.
func (r *Runner) Sources() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.sources))
	for src := range r.sources {
		out = append(out, src)
	}
	sort.Strings(out)
	return out
}

// pace spaces probes so a run never looks like a flood.
func (r *Runner) pace() {
	if r.perSecond <= 0 {
		return
	}
	wait := time.Second / time.Duration(r.perSecond)
	if next := r.last.Add(wait); time.Now().Before(next) {
		time.Sleep(time.Until(next))
	}
	r.last = time.Now()
}

// allowedMethod enforces the read-only rule: the application may see GET, HEAD,
// OPTIONS and TRACE, and POST only to the unimplemented probe path or the gate
// login.
func allowedMethod(method, path string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	case http.MethodPost:
		return path == gate.LoginPath || isProbePath(path)
	}
	return false
}

// isProbePath reports the random path attack traffic is addressed to. Preflight
// proved it answers the application's own 404, so a body sent there is read by
// nothing.
func isProbePath(path string) bool {
	return strings.HasPrefix(path, ProbePathPrefix) && !strings.Contains(path, "..")
}

// joinNote keeps both halves of a note readable, without a dangling separator.
func joinNote(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}
