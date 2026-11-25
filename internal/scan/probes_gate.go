package scan

// probes_gate.go tests the access gate itself: the login surface, session
// handling, the ban ladder's arming, the login sets available in each mode, and
// the three forward-auth checks. These probes are not differential — the gate
// has a known expected answer — so each one is judged against its expectation
// rather than against the upstream.
//
// Two rules shape the suite. It never sends more credential failures than the
// ban ladder tolerates (three failures from one address in ten minutes ban it),
// and it never signs in to the console hostname, even if a target row is
// misconfigured to point at it.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/gate"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

const (
	// StageGate labels the access-gate evidence rows.
	StageGate = "gate"
	// gateConfigMethod marks a check that reads configuration instead of
	// sending a request.
	gateConfigMethod = "CONFIG"
	// defaultGateFailures is the credential-failure budget. The ladder bans on
	// the third failure in ten minutes, so a run sends at most two.
	defaultGateFailures = 2
	// defaultGatePause spaces the two failure probes so they do not arrive as a
	// burst. A caller may shorten it, but only a test should.
	defaultGatePause = 30 * time.Second
)

// errGateFailureBudget stops a fifth credential failure from being sent.
var errGateFailureBudget = errors.New("the run's credential-failure budget is spent")

// GateAccount is the scan-only account the authenticated gate probes sign in
// with. The account is created for this purpose, bound to named hostnames, and
// signed out at the end of the run.
type GateAccount struct {
	Username string
	Password string
}

// GateOptions configures the gate suite.
type GateOptions struct {
	// Account is the scan-only gate account. Without one, every authenticated
	// probe is reported not tested, never passed.
	Account *GateAccount
	// ConsoleHost is the site's administration console. A target that is the
	// console is refused outright: a scanner must never sign in there.
	ConsoleHost string
	// MaxFailures caps the credential failures a run may cause. Zero means two.
	MaxFailures int
	// Pause spaces the two failure probes. Zero means the default; a negative
	// value sends them back to back, which only a test does.
	Pause time.Duration
	// SignOut ends the scan account's sessions. Without it, G5 is not tested.
	SignOut func(username string) error
	// ProviderDown says the operator arranged for the forward-auth provider to
	// be unreachable, the only way F1 can be proven.
	ProviderDown bool
}

// gateSuite is the state one gate run needs: the sequence number every evidence
// row carries and the failures spent so far.
type gateSuite struct {
	r        *Runner
	target   Target
	opts     GateOptions
	mode     string
	seq      int
	failures int
}

// RunGate runs the access-gate suite for one target and returns its evidence
// rows. Nothing is sent when the target is the console hostname or the gate is
// off.
func (r *Runner) RunGate(ctx context.Context, target Target, opts GateOptions) []model.ScanEvidence {
	s := &gateSuite{r: r, target: target, opts: opts, mode: gateMode(target.Proxy)}
	if s.opts.MaxFailures <= 0 {
		s.opts.MaxFailures = defaultGateFailures
	}
	if s.opts.Pause == 0 {
		s.opts.Pause = defaultGatePause
	}
	if s.opts.Pause < 0 {
		s.opts.Pause = 0
	}
	if host := strings.TrimSpace(s.opts.ConsoleHost); host != "" && strings.EqualFold(host, target.Proxy.Hostname) {
		return []model.ScanEvidence{s.evidence(
			gateProbe("gate", http.MethodGet, "/", nil), NotRun,
			fmt.Sprintf("refused: %s is the console hostname and the scanner must never sign in to the console", host), nil)}
	}
	if s.mode == "off" {
		return []model.ScanEvidence{s.g13()}
	}

	rows := []model.ScanEvidence{s.g13(), s.g1(ctx)}
	rows = append(rows, s.g2(ctx)...)
	if s.mode == "forward_auth" {
		rows = append(rows, s.f1(ctx), s.f2(ctx), s.f3(ctx))
		rows = append(rows, s.evidence(
			gateProbe("G3-G12", gateConfigMethod, target.Proxy.Hostname, nil), NotApplicable,
			"the gate is an external forward-auth provider, so its session controls are not ours to test", nil))
		return rows
	}

	rows = append(rows,
		s.g3(ctx), s.g4(ctx), s.g5(ctx), s.g6(ctx), s.g7(), s.g8(ctx), s.g9(ctx), s.g10(ctx),
		s.g11Cache(ctx), s.g11SignedIn(ctx))
	rows = append(rows, s.g12(ctx)...)
	if s.opts.SignOut != nil && s.opts.Account != nil {
		// The run ends its own session even when G5 is not the last check, so a
		// scanner session never outlives the scan.
		_ = s.opts.SignOut(s.opts.Account.Username)
	}
	return rows
}

func gateMode(p model.Proxy) string {
	if p.GateMode == "" {
		return "off"
	}
	return p.GateMode
}

func gateProbe(class, method, path string, header http.Header) Probe {
	return Probe{Stage: StageGate, Class: class, Method: method, Path: path, Header: header}
}

// evidence turns one check into a row. a is nil for a check that sent no
// request.
func (s *gateSuite) evidence(p Probe, v Verdict, note string, a *answer) model.ScanEvidence {
	s.seq++
	ev := model.ScanEvidence{
		Seq: s.seq, Stage: StageGate, Class: p.Class, Method: p.Method, Path: p.Path,
		Verdict: string(v), Detail: RedactRequest(p), Note: note,
	}
	if a != nil {
		ev.WANStatus = a.status
		ev.WANHash = a.hash()
	}
	return ev
}

func (s *gateSuite) send(ctx context.Context, p Probe) (answer, error) {
	s.r.pace()
	return s.r.send(ctx, s.r.wanClient, s.r.wan, s.r.tagProbe(p, s.seq+1))
}

// challenged reports whether the gate itself refused to serve the app. A bare
// 401/403 is only the gate's answer in forward-auth mode, where the provider's
// verdict is relayed; otherwise it could be an edge rule, and counting that as
// the gate would be a false pass.
func (s *gateSuite) challenged(a answer) bool {
	if isGatePage(a) {
		return true
	}
	if a.status >= 300 && a.status < 400 {
		return a.header.Get("Location") != ""
	}
	if s.mode == "forward_auth" {
		return a.status == http.StatusUnauthorized || a.status == http.StatusForbidden
	}
	return false
}

// g1 sends an unauthenticated request to the site root.
func (s *gateSuite) g1(ctx context.Context) model.ScanEvidence {
	p := gateProbe("G1", http.MethodGet, "/", nil)
	a, err := s.send(ctx, p)
	if err != nil {
		return s.evidence(p, NotRun, "the published path did not answer: "+shortError(err), nil)
	}
	if s.challenged(a) {
		return s.evidence(p, BlockedGate, "an unauthenticated request was challenged", &a)
	}
	return s.evidence(p, ReachedBackend, "the application answered an unauthenticated request without a challenge", &a)
}

// g2 asks for application assets that must not be served before sign-in.
func (s *gateSuite) g2(ctx context.Context) []model.ScanEvidence {
	var rows []model.ScanEvidence
	for _, path := range []string{"/favicon.ico", "/assets/app.js"} {
		p := gateProbe("G2", http.MethodGet, path, nil)
		a, err := s.send(ctx, p)
		if err != nil {
			rows = append(rows, s.evidence(p, NotRun, "the published path did not answer: "+shortError(err), nil))
			continue
		}
		if s.challenged(a) {
			rows = append(rows, s.evidence(p, BlockedGate, "the gate answered before the asset was served", &a))
			continue
		}
		rows = append(rows, s.evidence(p, ReachedBackend, "an application asset was served before authentication", &a))
	}
	return rows
}

// g3 signs in, changes one byte of the session cookie and replays it.
func (s *gateSuite) g3(ctx context.Context) model.ScanEvidence {
	p := gateProbe("G3", http.MethodGet, "/", nil)
	if s.opts.Account == nil {
		return s.evidence(p, NotRun, "not tested: no scan-only gate account is bound to this hostname", nil)
	}
	session, err := s.signIn(ctx)
	if err != nil {
		return s.evidence(p, NotRun, "not tested: "+err.Error(), nil)
	}
	p.Header = http.Header{"Cookie": {gate.CookieName + "=" + tampered(session)}}
	a, sendErr := s.send(ctx, p)
	if sendErr != nil {
		return s.evidence(p, NotRun, "the published path did not answer: "+shortError(sendErr), nil)
	}
	if s.challenged(a) {
		return s.evidence(p, BlockedGate, "a session cookie with one byte changed was refused", &a)
	}
	return s.evidence(p, Failed, "a session cookie with one byte changed still opened the site", &a)
}

// g4 presents a fixed cookie before signing in and asks for a different one
// afterwards.
func (s *gateSuite) g4(ctx context.Context) model.ScanEvidence {
	p := gateProbe("G4", http.MethodPost, gate.LoginPath, nil)
	if s.opts.Account == nil {
		return s.evidence(p, NotRun, "not tested: no scan-only gate account is bound to this hostname", nil)
	}
	const fixated = "wafscan-fixated-session"
	user, pass := s.credentials()
	a, err := s.login(ctx, user, pass, "/", fixated)
	if err != nil {
		return s.evidence(p, NotRun, "the gate login did not answer: "+shortError(err), nil)
	}
	if a.status != http.StatusSeeOther && a.status != http.StatusFound {
		return s.evidence(p, Failed, fmt.Sprintf("the sign-in answered HTTP %d instead of redirecting", a.status), &a)
	}
	if rotated := sessionValue(a); rotated == "" || rotated == fixated {
		return s.evidence(p, Failed, "the session cookie was not replaced on sign-in", &a)
	}
	return s.evidence(p, Passed, "the session cookie was replaced on sign-in", &a)
}

// g5 replays a session cookie after the session has been revoked.
func (s *gateSuite) g5(ctx context.Context) model.ScanEvidence {
	p := gateProbe("G5", http.MethodGet, "/", nil)
	if s.opts.Account == nil {
		return s.evidence(p, NotRun, "not tested: no scan-only gate account is bound to this hostname", nil)
	}
	if s.opts.SignOut == nil {
		return s.evidence(p, NotRun, "not tested: this run has no way to end a gate session", nil)
	}
	session, err := s.signIn(ctx)
	if err != nil {
		return s.evidence(p, NotRun, "not tested: "+err.Error(), nil)
	}
	if err := s.opts.SignOut(s.opts.Account.Username); err != nil {
		return s.evidence(p, NotRun, "not tested: the scan session could not be revoked: "+shortError(err), nil)
	}
	p.Header = http.Header{"Cookie": {gate.CookieName + "=" + session}}
	a, sendErr := s.send(ctx, p)
	if sendErr != nil {
		return s.evidence(p, NotRun, "the published path did not answer: "+shortError(sendErr), nil)
	}
	if s.challenged(a) {
		return s.evidence(p, BlockedGate, "the old session cookie was refused after sign-out", &a)
	}
	return s.evidence(p, Failed, "a signed-out session cookie still opened the site", &a)
}

// g6 sends two wrong passphrases, spaced, and compares the answers.
func (s *gateSuite) g6(ctx context.Context) model.ScanEvidence {
	p := gateProbe("G6", http.MethodPost, gate.LoginPath, nil)
	if s.mode != "passphrase" {
		return s.evidence(p, NotApplicable, "the gate uses accounts, so the passphrase failure probe does not apply", nil)
	}
	return s.uniformFailures(ctx, p, "", "wafscan-wrong-passphrase", "", "wafscan-other-wrong-passphrase")
}

// g7 reports the ladder as armed. The two deliberate failures are the evidence;
// the thresholds come from the gate itself so the report cannot drift from the
// code that bans.
func (s *gateSuite) g7() model.ScanEvidence {
	p := gateProbe("G7", gateConfigMethod, s.target.Proxy.Hostname, nil)
	return s.evidence(p, Passed, fmt.Sprintf(
		"armed, not tripped: %d deliberate failure(s) this run; the ladder bans at %d failures in ten minutes, %d in 24 hours and after %d days with failures",
		s.failures, gate.BanFailures10m, gate.BanFailures24h, gate.BanCleanDays), nil)
}

// g8 compares a wrong password for the real scan account with one for a name
// that does not exist.
func (s *gateSuite) g8(ctx context.Context) model.ScanEvidence {
	p := gateProbe("G8", http.MethodPost, gate.LoginPath, nil)
	if s.mode != "accounts" && s.mode != "accounts_totp" {
		return s.evidence(p, NotApplicable, "the gate is a shared passphrase, so account enumeration does not apply", nil)
	}
	if s.opts.Account == nil {
		return s.evidence(p, NotRun, "not tested: no scan-only gate account is bound to this hostname", nil)
	}
	path, err := NewProbePath()
	if err != nil {
		return s.evidence(p, NotRun, "not tested: "+err.Error(), nil)
	}
	unknown := "wafscan-" + strings.TrimPrefix(path, ProbePathPrefix)
	return s.uniformFailures(ctx, p, s.opts.Account.Username, "wafscan-wrong-password",
		unknown, "wafscan-wrong-password")
}

// g9 posts a login from another origin.
func (s *gateSuite) g9(ctx context.Context) model.ScanEvidence {
	p := gateProbe("G9", http.MethodPost, gate.LoginPath, http.Header{
		"Content-Type": {"application/x-www-form-urlencoded"},
		"Origin":       {"https://evil.example"},
	})
	user, pass := "wafscan-unknown", "wafscan-wrong-password"
	if s.opts.Account != nil {
		user, pass = s.credentials()
	}
	p.Body = url.Values{"username": {user}, "password": {pass}, "next": {"/"}}.Encode()
	a, err := s.send(ctx, p)
	if err != nil {
		return s.evidence(p, NotRun, "the published path did not answer: "+shortError(err), nil)
	}
	if a.status != http.StatusForbidden {
		return s.evidence(p, Failed, fmt.Sprintf("a cross-origin login answered HTTP %d instead of 403", a.status), &a)
	}
	if sessionValue(a) != "" {
		return s.evidence(p, Failed, "a cross-origin login was refused but still set a session cookie", &a)
	}
	return s.evidence(p, BlockedGate, "the cross-origin login was refused without a session", &a)
}

// g10 signs in twice with a next value that tries to leave the site.
func (s *gateSuite) g10(ctx context.Context) model.ScanEvidence {
	p := gateProbe("G10", http.MethodPost, gate.LoginPath, nil)
	if s.opts.Account == nil {
		return s.evidence(p, NotRun, "not tested: no scan-only gate account is bound to this hostname", nil)
	}
	user, pass := s.credentials()
	var last answer
	for _, next := range []string{"//evil.example", `/\evil.example`} {
		a, err := s.login(ctx, user, pass, next, "")
		if err != nil {
			return s.evidence(p, NotRun, "the gate login did not answer: "+shortError(err), nil)
		}
		last = a
		location := a.header.Get("Location")
		if location == "" {
			return s.evidence(p, Failed, fmt.Sprintf("the sign-in with next=%q did not redirect", next), &a)
		}
		if !safeNext(location, s.target.Proxy.Hostname) {
			return s.evidence(p, Failed, fmt.Sprintf("next=%q redirected to %q", next, location), &a)
		}
	}
	return s.evidence(p, Passed, "both next values stayed on the site after sign-in", &last)
}

// g11Cache checks the challenge carries no-store.
func (s *gateSuite) g11Cache(ctx context.Context) model.ScanEvidence {
	p := gateProbe("G11", http.MethodGet, "/", nil)
	a, err := s.send(ctx, p)
	if err != nil {
		return s.evidence(p, NotRun, "the published path did not answer: "+shortError(err), nil)
	}
	if !strings.Contains(strings.ToLower(a.header.Get("Cache-Control")), "no-store") {
		return s.evidence(p, Failed, "the gate challenge is cacheable: Cache-Control "+a.header.Get("Cache-Control"), &a)
	}
	return s.evidence(p, Passed, "the gate challenge is no-store", &a)
}

// g11SignedIn fetches the site unauthenticated after a successful sign-in, so a
// shared cache cannot hand out the signed-in page.
func (s *gateSuite) g11SignedIn(ctx context.Context) model.ScanEvidence {
	p := gateProbe("G11", http.MethodGet, "/", nil)
	if s.opts.Account == nil {
		return s.evidence(p, NotRun, "not tested: no scan-only gate account is bound to this hostname", nil)
	}
	if _, err := s.signIn(ctx); err != nil {
		return s.evidence(p, NotRun, "not tested: "+err.Error(), nil)
	}
	a, err := s.send(ctx, p)
	if err != nil {
		return s.evidence(p, NotRun, "the published path did not answer: "+shortError(err), nil)
	}
	if s.challenged(a) {
		return s.evidence(p, BlockedGate, "an unauthenticated fetch could not return the signed-in page", &a)
	}
	return s.evidence(p, Failed, "an unauthenticated fetch returned the site after a sign-in", &a)
}

// g12 tries the shapes that have historically walked around path-level gates.
func (s *gateSuite) g12(ctx context.Context) []model.ScanEvidence {
	shapes := []struct {
		path   string
		header http.Header
		note   string
	}{
		{path: "//path"},
		{path: "/path;.css"},
		{path: "/PATH"},
		{path: "/path%00", note: "net/http escapes a raw NUL, so the gate sees this double-encoded"},
		{path: "/path/..;/"},
		{path: "/", header: http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}}},
		{path: "/", header: http.Header{"Range": {"bytes=0-1"}}},
	}
	var rows []model.ScanEvidence
	for _, shape := range shapes {
		p := gateProbe("G12", http.MethodGet, shape.path, shape.header)
		a, err := s.send(ctx, p)
		if err != nil {
			rows = append(rows, s.evidence(p, NotRun, "the published path did not answer: "+shortError(err), nil))
			continue
		}
		if s.challenged(a) {
			rows = append(rows, s.evidence(p, BlockedGate, shape.note, &a))
			continue
		}
		rows = append(rows, s.evidence(p, Failed, joinNote(shape.note, "this shape bypassed the gate"), &a))
	}
	return rows
}

// g13 records what the site's gate mode means for the scan.
func (s *gateSuite) g13() model.ScanEvidence {
	p := gateProbe("G13", gateConfigMethod, s.target.Proxy.Hostname, nil)
	if s.mode == "off" {
		return s.evidence(p, NotApplicable,
			"the gate is off; if this hostname serves an admin UI that is a configuration finding, not an attack", nil)
	}
	return s.evidence(p, Passed, "gate mode "+s.mode+" is on", nil)
}

// f1 asks for the site while the provider is unreachable. Only a run the
// operator arranged may claim this.
func (s *gateSuite) f1(ctx context.Context) model.ScanEvidence {
	p := gateProbe("F1", http.MethodGet, "/", nil)
	if !s.opts.ProviderDown {
		return s.evidence(p, NotRun,
			"not tested: the forward-auth provider was not made unreachable, so its failure behavior is unproven", nil)
	}
	a, err := s.send(ctx, p)
	if err != nil {
		return s.evidence(p, NotRun, "the published path did not answer: "+shortError(err), nil)
	}
	if a.status == http.StatusServiceUnavailable {
		return s.evidence(p, Passed, "the site answered 503 with the provider unreachable", &a)
	}
	return s.evidence(p, Failed, fmt.Sprintf("the site answered HTTP %d with the provider unreachable", a.status), &a)
}

// f2 sends the identity headers a proxy in front of the provider would add.
func (s *gateSuite) f2(ctx context.Context) model.ScanEvidence {
	header := http.Header{
		"X-Auth-Request-User": {"wafscan-attacker"},
		"X-Forwarded-User":    {"wafscan-attacker"},
		"Remote-User":         {"wafscan-attacker"},
	}
	p := gateProbe("F2", http.MethodGet, "/", header)
	a, err := s.send(ctx, p)
	if err != nil {
		return s.evidence(p, NotRun, "the published path did not answer: "+shortError(err), nil)
	}
	if s.challenged(a) {
		return s.evidence(p, BlockedGate, "client-supplied identity headers did not open the site", &a)
	}
	return s.evidence(p, Failed, "a client-supplied identity header was trusted", &a)
}

// f3 expects the gate to redirect to the provider.
func (s *gateSuite) f3(ctx context.Context) model.ScanEvidence {
	p := gateProbe("F3", http.MethodGet, "/", nil)
	a, err := s.send(ctx, p)
	if err != nil {
		return s.evidence(p, NotRun, "the published path did not answer: "+shortError(err), nil)
	}
	if a.status >= 300 && a.status < 400 && a.header.Get("Location") != "" {
		return s.evidence(p, Passed, "the gate redirects to the provider", &a)
	}
	return s.evidence(p, Failed, fmt.Sprintf("the gate answered HTTP %d instead of redirecting to the provider", a.status), &a)
}

// uniformFailures sends two credential failures, spaced, and compares them.
// Both are counted against the budget before they are sent.
func (s *gateSuite) uniformFailures(ctx context.Context, p Probe, user1, pass1, user2, pass2 string) model.ScanEvidence {
	if s.failures+2 > s.opts.MaxFailures {
		return s.evidence(p, NotRun, fmt.Sprintf(
			"not tested: the run may cause %d credential failure(s) and the ladder bans on the third in ten minutes",
			s.opts.MaxFailures), nil)
	}
	first, err := s.badLogin(ctx, user1, pass1)
	if err != nil {
		return s.evidence(p, NotRun, "the first failure did not answer: "+shortError(err), nil)
	}
	if s.opts.Pause > 0 {
		select {
		case <-ctx.Done():
			return s.evidence(p, NotRun, "the run was cancelled between the two failures", nil)
		case <-time.After(s.opts.Pause):
		}
	}
	second, err := s.badLogin(ctx, user2, pass2)
	if err != nil {
		return s.evidence(p, NotRun, "the second failure did not answer: "+shortError(err), nil)
	}
	if first.status != second.status || len(first.body) != len(second.body) || first.hash() != second.hash() {
		return s.evidence(p, Failed, fmt.Sprintf(
			"the two failures differ: HTTP %d/%d, %d/%d bytes",
			first.status, second.status, len(first.body), len(second.body)), &second)
	}
	return s.evidence(p, Passed, fmt.Sprintf(
		"two failures answered identically: HTTP %d, %d bytes", first.status, len(first.body)), &second)
}

// badLogin sends one credential failure, refusing past the budget.
func (s *gateSuite) badLogin(ctx context.Context, user, pass string) (answer, error) {
	if s.failures >= s.opts.MaxFailures {
		return answer{}, errGateFailureBudget
	}
	s.failures++
	return s.login(ctx, user, pass, "/", "")
}

// login posts to the gate. cookie carries a pre-set session value when the
// check is about session handling.
func (s *gateSuite) login(ctx context.Context, username, password, next, cookie string) (answer, error) {
	header := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	if cookie != "" {
		header.Set("Cookie", gate.CookieName+"="+cookie)
	}
	return s.send(ctx, Probe{
		Stage: StageGate, Class: "gate-login", Method: http.MethodPost, Path: gate.LoginPath,
		Header: header,
		Body:   url.Values{"username": {username}, "password": {password}, "next": {next}}.Encode(),
	})
}

// credentials returns the form values a sign-in needs. A shared passphrase has
// no username field, so the operator stores the passphrase as the account's
// password.
func (s *gateSuite) credentials() (string, string) {
	if s.mode == "passphrase" {
		return "", s.opts.Account.Password
	}
	return s.opts.Account.Username, s.opts.Account.Password
}

// signIn opens a session and returns its cookie value.
func (s *gateSuite) signIn(ctx context.Context) (string, error) {
	user, pass := s.credentials()
	a, err := s.login(ctx, user, pass, "/", "")
	if err != nil {
		return "", fmt.Errorf("the gate login did not answer: %w", err)
	}
	if a.status != http.StatusSeeOther && a.status != http.StatusFound {
		return "", fmt.Errorf("the gate answered HTTP %d to the scan account, want a redirect", a.status)
	}
	value := sessionValue(a)
	if value == "" {
		return "", errors.New("the gate set no session cookie")
	}
	return value, nil
}

// sessionValue returns the gate session cookie an answer set, if any.
func sessionValue(a answer) string {
	for _, c := range (&http.Response{Header: a.header}).Cookies() {
		if c.Name == gate.CookieName && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

// tampered changes one byte of a session value so it can no longer be the one
// the gate issued.
func tampered(value string) string {
	if value == "" {
		return "x"
	}
	b := []byte(value)
	i := len(b) / 2
	if b[i] == 'a' {
		b[i] = 'b'
	} else {
		b[i] = 'a'
	}
	return string(b)
}

// safeNext reports whether a post-login redirect stays on the site.
func safeNext(location, host string) bool {
	if location == "" || strings.HasPrefix(location, "//") || strings.Contains(location, `\`) {
		return false
	}
	u, err := url.Parse(location)
	if err != nil {
		return false
	}
	return u.Host == "" || strings.EqualFold(u.Host, host)
}
