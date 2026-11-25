package scan

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/gate"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// ErrAborted is returned when the published path refused the scanner often
// enough that carrying on would only deepen a rate limit or a ban.
var ErrAborted = errors.New("scan aborted: the published path kept refusing")

const (
	maxRefusals    = 5
	probeTimeout   = 5 * time.Second
	maxAnswerBytes = 256 << 10
	scanUserAgent  = "wafproxy-scan/1.0"
)

// Runner sends probes through the published path and straight to the upstream.
type Runner struct {
	wan, upstream       Endpoint
	wanClient, upClient *http.Client
	perSecond           int
	last                time.Time
}

// NewRunner builds a runner for one target. perSecond paces the probes; zero
// sends them as fast as the target answers, which tests use.
func NewRunner(wan, upstream Endpoint, perSecond int) *Runner {
	return &Runner{
		wan:       wan,
		upstream:  upstream,
		wanClient: probeClient(false),
		upClient:  probeClient(upstream.Insecure),
		perSecond: perSecond,
	}
}

func probeClient(insecure bool) *http.Client {
	return &http.Client{
		Timeout: probeTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
		// A redirect is part of the answer: following it would hide the gate.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Run sends every probe and returns one evidence row per probe. It stops early
// when the published path keeps refusing, returning the rows so far.
func (r *Runner) Run(ctx context.Context, probes []Probe) ([]model.ScanEvidence, error) {
	out := make([]model.ScanEvidence, 0, len(probes))
	refusals := 0
	for i, p := range probes {
		if err := ctx.Err(); err != nil {
			return downgraded(out, probes), err
		}
		if !allowedMethod(p.Method, p.Path) {
			out = append(out, model.ScanEvidence{
				Seq: i, Stage: p.Stage, Class: p.Class, Method: p.Method, Path: p.Path,
				Verdict: string(NotRun), Note: "method not allowed", Detail: RedactRequest(p),
			})
			continue
		}
		r.pace()
		ev := r.probe(ctx, i, p)
		out = append(out, ev)
		if wanRefusal(ev.WANStatus) {
			refusals++
			if refusals >= maxRefusals {
				return downgraded(out, probes), ErrAborted
			}
			continue
		}
		refusals = 0
	}
	return downgraded(out, probes), nil
}

// probe sends one request through both paths and compares the answers. A POST
// is the gate login and never reaches the application.
func (r *Runner) probe(ctx context.Context, seq int, p Probe) model.ScanEvidence {
	ev := model.ScanEvidence{
		Seq: seq, Stage: p.Stage, Class: p.Class, Method: p.Method, Path: p.Path,
		Detail: RedactRequest(p),
	}
	wan, err := r.send(ctx, r.wanClient, r.wan, p)
	if err != nil {
		ev.Verdict = string(NotRun)
		ev.Note = "the published path did not answer: " + shortError(err)
		return ev
	}
	ev.WANStatus = wan.status
	ev.WANHash = wan.hash()

	if p.Method == http.MethodPost {
		// Only the gate login is a POST, and the application must never see it.
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
		ev.Note = "the upstream did not answer: " + shortError(err)
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

	u := *ep.URL
	u.Path = strings.TrimSuffix(u.Path, "/") + p.Path
	u.RawQuery = p.Query
	req, err := http.NewRequestWithContext(ctx, p.Method, u.String(), strings.NewReader(p.Body))
	if err != nil {
		return answer{}, err
	}
	req.Host = ep.Host
	for name, values := range p.Header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
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
	return answer{status: resp.StatusCode, body: body}, nil
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

// allowedMethod enforces the read-only rule: the application may see GET, HEAD
// and OPTIONS, and the gate login may see POST.
func allowedMethod(method, path string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	case http.MethodPost:
		return path == gate.LoginPath
	}
	return false
}

// downgraded turns a block into inconclusive when the benign control for the
// same class was refused too: a blanket refusal is not a rule.
func downgraded(out []model.ScanEvidence, probes []Probe) []model.ScanEvidence {
	refused := map[string]bool{}
	for i, p := range probes {
		if i < len(out) && p.Control && (out[i].Verdict == string(BlockedWAF) || out[i].Verdict == string(BlockedGate)) {
			refused[p.Class] = true
		}
	}
	if len(refused) == 0 {
		return out
	}
	for i := range out {
		if refused[out[i].Class] && out[i].Verdict == string(BlockedWAF) {
			out[i].Verdict = string(Inconclusive)
			out[i].Note = "the control request was refused too"
		}
	}
	return out
}
