package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/botfilter"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/botguard"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/policy"
)

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	// The scheme the browser used, taken before RemoteAddr becomes the client
	// address: the upstream needs it for absolute URLs and for the CSRF origin
	// check, and a trusted front proxy knows it better than this plain hop does.
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if s.d.ClientIP != nil {
		scheme = s.d.ClientIP.SchemeFromRequest(r)
	}
	// An HTTP/1.1 or HTTP/2 client learns about the QUIC listener from the
	// answer it already receives; setAltSvc decides whether there is one.
	s.setAltSvc(w, r)
	// One trusted-proxy decision per request, taken before any forwarding header
	// is stripped: the access lists, the ban engine, GeoIP, the access log and
	// the upstream all read the same address from RemoteAddr afterwards.
	if s.d.ClientIP != nil {
		if addr, ok := s.d.ClientIP.FromRequest(r); ok {
			r.RemoteAddr = net.JoinHostPort(addr.String(), "0")
		}
	}
	host := normalizeHost(r.Host)
	e := s.lookup(host)

	rw := &responseWriter{ResponseWriter: w, strict: true, requestID: requestIDFor(r), secure: r.TLS != nil}
	if e == nil {
		// A configured decoy hostname is a deliberate scan target: ban the source
		// before falling back to the silent unknown-host blackhole.
		if s.d.Policy.DecoyHost(host) {
			ip := clientAddr(r)
			loc := s.d.Geo.Lookup(ip)
			// Only write the ban once, but upgrade an existing temporary ban:
			// a decoy hostname must always end in a permanent ban.
			if rec, banned := s.d.Bans.Match(ip); !banned || !rec.Permanent {
				go func() {
					_, _ = s.d.Bans.Add(ip.String(), "decoy hostname requested: "+host, "decoy", "policy", 0)
				}()
			}
			s.record(model.Event{TS: start, Host: host, SrcIP: ip.String(),
				Country: loc.Country, City: loc.City, ASN: loc.ASN, Lat: loc.Lat, Lon: loc.Lon,
				Method: r.Method, Path: r.URL.Path, Stage: "decoy-host", RuleID: "decoy-host",
				RuleMsg: "decoy hostname", Action: "ban", Status: http.StatusForbidden,
				UA: r.UserAgent(), Sample: 1})
			uniformError(rw, http.StatusForbidden)
			return
		}
		s.blackhole(w, r, host, start)
		return
	}
	if e.proxy.Fingerprint == "minimal" {
		rw.strict = false
	}
	// A site and a single client are bounded separately from the process-wide
	// budget, so one busy host cannot starve the others.
	ip := clientAddr(r)
	if !e.site.acquire() {
		rw.Header().Set("Retry-After", "1")
		uniformError(rw, http.StatusServiceUnavailable)
		return
	}
	defer e.site.release()
	if !e.clients.acquire(ip.String()) {
		rw.Header().Set("Retry-After", "1")
		uniformError(rw, http.StatusTooManyRequests)
		return
	}
	defer e.clients.release(ip.String())
	rw.protection = e.protection
	// HTTPS enforcement happens before the WAF: a plain-HTTP request is
	// redirected rather than inspected, so it reaches the same policy once it
	// has been upgraded instead of skipping the TLS-only path.
	if e.protection != nil && e.protection.ForceHTTPS && r.TLS == nil {
		http.Redirect(rw, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
		return
	}

	loc := s.d.Geo.Lookup(ip)
	event := model.Event{
		TS: start, ProxyID: &e.proxy.ID, Host: host, SrcIP: ip.String(), RequestID: rw.requestID,
		Country: loc.Country, City: loc.City, ASN: loc.ASN, Lat: loc.Lat, Lon: loc.Lon,
		Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, UA: r.UserAgent(), Sample: 1,
	}
	blocked := false
	defer func() {
		event.Status = rw.Status()
		event.BytesOut = rw.Size()
		event.LatencyMS = time.Since(start).Milliseconds()
		if blocked {
			// Preserve the specific outcome (ban, challenge) so the log does not
			// flatten every rejection into "block".
			if event.Action == "" || event.Action == "allow" {
				event.Action = "block"
			}
		} else if event.Action == "" {
			event.Action = "allow"
		}
		s.record(event)
		var b int64
		if blocked {
			b = 1
		}
		s.d.Metrics.Count(e.proxy.ID, 1, b, event.BytesIn, event.BytesOut)
		s.d.Metrics.CountSource(e.proxy.ID, event.SrcIP, event.BytesOut)
	}()

	if !e.proxy.Enabled {
		blocked = true
		event.Stage, event.RuleID, event.RuleMsg = "disabled", "proxy-disabled", "proxy disabled"
		uniformError(rw, http.StatusServiceUnavailable)
		return
	}
	if badRequestFraming(r) {
		blocked = true
		event.Stage, event.RuleID, event.RuleMsg = "protocol", "framing", "invalid request framing"
		uniformError(rw, http.StatusBadRequest)
		return
	}
	cleanPath, ok := cleanPathSegments(r.URL.Path)
	if !ok {
		blocked = true
		event.Stage, event.RuleID, event.RuleMsg = "protocol", "path", "path contains a NUL byte"
		uniformError(rw, http.StatusBadRequest)
		return
	}
	if cleanPath != r.URL.Path {
		// Dot segments are resolved by the backend, so inspecting "/x/../.env"
		// while /x/.env is served would let a path skip decoy and WAF rules.
		// Canonicalise before every check and before forwarding.
		r.URL.Path = cleanPath
		r.URL.RawPath = ""
	}
	if e.proxy.Maintenance {
		blocked = true
		event.Stage = "maintenance"
		maintenancePage(rw)
		return
	}

	// Header-only screening runs before the body is buffered so banned, blocked
	// and rate-limited clients cannot consume request memory.
	preq := &policy.Request{
		Proxy: &e.proxy, Host: host, Method: r.Method, Path: r.URL.Path,
		Query: r.URL.RawQuery, UA: r.UserAgent(), Addr: ip, Loc: loc, HTTP: r,
	}

	verdict := s.d.Policy.Screen(preq)
	if verdict.Action == "challenge" {
		blocked = true
		event.Stage, event.RuleID, event.RuleMsg = verdict.Stage, verdict.Rule, verdict.Reason
		event.Action = "challenge"
		// A solved challenge cookie satisfies a feed challenge too; otherwise a
		// challenged visitor would loop forever on the same feed entry.
		if verdict.Stage == "feed" && s.d.Bots.Verified(r, ip.String()) {
			// The visitor already solved a challenge: carry on and let the
			// deferred logger record the request as allowed.
			blocked = false
			event.Action = ""
		} else if s.d.Bots.HandleChallenge(rw, r, &e.proxy, ip.String()) {
			return
		} else {
			// A challenge that cannot be served (bot protection is off for this
			// proxy) must not silently downgrade the feed rule to "allow".
			event.Action = "block"
			uniformError(rw, http.StatusForbidden)
			return
		}
	}
	if verdict.Action == "block" || verdict.Action == "ban" {
		blocked = true
		event.Stage, event.RuleID, event.RuleMsg = verdict.Stage, verdict.Rule, verdict.Reason
		event.Action = verdict.Action
		respondVerdict(rw, verdict)
		return
	}
	if verdict.Action == "log" {
		event.Stage, event.RuleID, event.RuleMsg = verdict.Stage, verdict.Rule, verdict.Reason
	}

	// The filter runs before the challenge: a crawler the operator asked to
	// refuse should not be asked to prove it is a browser first.
	if settings := s.d.Policy.Settings(e.proxy.SiteID); settings.Enabled {
		if denied, rule := botfilter.Blocked(r.UserAgent(), settings.BotFilter, settings.BotFilterAllow); denied {
			blocked = true
			event.Stage, event.RuleID = "bot-filter", "bot:"+rule
			event.RuleMsg = "user agent matches the " + rule + " bot rule"
			event.Action = "block"
			uniformError(rw, http.StatusForbidden)
			return
		}
	}

	if r.URL.Path == botguard.SolvePath {
		if s.d.Bots.HandleChallenge(rw, r, &e.proxy, ip.String()) {
			event.Stage, event.Action = "bot-challenge", "challenge"
			return
		}
	}
	if e.proxy.BotLevel != "" && e.proxy.BotLevel != "off" &&
		botguard.BrowserLike(r) && !s.d.Bots.Verified(r, ip.String()) {
		if s.d.Bots.HandleChallenge(rw, r, &e.proxy, ip.String()) {
			event.Stage, event.Action = "bot-challenge", "challenge"
			blocked = true
			return
		}
	}

	// One cache decision serves both the cache-first check and the writer.
	cacheable := cacheableRequest(r)
	cacheKeyOf := ""
	if cacheable {
		cacheKeyOf = cacheKey(r)
	}

	// Cache-first answers a cached GET here, before the CRS. The site opts in
	// (cache_pre_waf), a gated site never gets it, and a request that carries a
	// body is not answered from a stored response.
	if e.cachePreWAF && r.ContentLength == 0 && cacheable {
		key := cacheKeyOf
		if entry, ok := e.cache.get(key); ok {
			enc, acceptable := negotiateEncoding(r.Header.Get("Accept-Encoding"))
			if !acceptable {
				blocked = true
				notAcceptable(rw, &event)
				return
			}
			e.serveCached(rw, key, entry, enc)
			event.Stage, event.RuleID = "cache", "cache-hit"
			return
		}
	}

	limit := s.hardBody
	if e.proxy.MaxBody > 0 {
		limit = e.proxy.MaxBody
	}
	// A skip path streams its body to the upstream: the WAF cannot inspect bytes
	// it never holds, so the exemption is recorded on the event and the rest of
	// the pipeline still applies. An entry may name lists to trust only those
	// sources.
	skipBody := bodySkipped(e.proxy.BodySkip, r.Method, r.URL.Path, func(ids []int64) bool {
		return s.d.Policy.InList(preq, ids)
	})
	// The content-type and method policy rules refuse a raw PUT upload before
	// any body is read, which would defeat the exemption it is meant to serve.
	preq.BodyStreamed = skipBody
	if skipBody {
		event.Stage, event.RuleID = "body-skip", "path"
		event.RuleMsg = "request body is streamed without inspection"
		cr := newStallReader(r.Body, s.skipStall, http.NewResponseController(rw))
		r.Body = cr
		defer func() {
			event.BytesIn = cr.bytes()
			// Clear the deadline so the connection is usable again, and say why the
			// upload ended when the client simply stopped sending.
			_ = cr.rc.SetReadDeadline(time.Time{})
			if cr.didStall() {
				event.Stage, event.RuleID = "body-skip", "stalled"
				event.RuleMsg = "the client sent nothing for " + s.skipStall.String()
			}
		}()
		preq.Body = nil
	} else {
		// A body that cannot fit in the buffer is refused now rather than queued
		// behind a full budget: the answer is 413 either way, and the client
		// should hear it without a wait.
		if r.ContentLength > limit {
			blocked = true
			event.Stage, event.RuleID = "body-limit", "too-large"
			uniformError(rw, http.StatusRequestEntityTooLarge)
			return
		}
		reserved := estimateBody(r, limit)
		release, reason := s.budget.reserve(r.Context(), reserved, e.queue)
		if release == nil {
			blocked = true
			event.Stage, event.RuleID = "capacity", "queue-timeout"
			if reason == "bytes" {
				event.RuleID = "budget-too-large"
			}
			rw.Header().Set("Retry-After", "1")
			uniformError(rw, http.StatusServiceUnavailable)
			return
		}
		// The body deadline is the client's: it starts once the request owns a
		// budget slot and is cleared before the forward, so a slow upstream is
		// governed by its own timeout instead.
		rc := http.NewResponseController(rw)
		// A request that cannot carry a body has nothing to wait for, so a GET
		// avoids the two deadline syscalls.
		hasBody := r.ContentLength != 0 || len(r.TransferEncoding) > 0
		if e.bodyTimeout > 0 && hasBody {
			_ = rc.SetReadDeadline(time.Now().Add(e.bodyTimeout))
		}
		// Bytes past the reservation are charged as they arrive: a body with no
		// declared length would otherwise be read up to the ceiling while only
		// its 64 KiB estimate is accounted for.
		var over int64
		read, tooLarge, err := readBody(r, limit, reserved, func(n int64) bool {
			if !s.budget.charge(n) {
				return false
			}
			over += n
			return true
		})
		if e.bodyTimeout == 0 || hasBody {
			_ = rc.SetReadDeadline(time.Time{})
		}
		body := read
		defer func() {
			release()
			s.budget.uncharge(over)
		}()
		if errors.Is(err, errBudgetFull) {
			blocked = true
			event.Stage, event.RuleID = "capacity", "budget-too-large"
			rw.Header().Set("Retry-After", "1")
			uniformError(rw, http.StatusServiceUnavailable)
			return
		}
		if tooLarge {
			blocked = true
			event.Stage, event.RuleID = "body-limit", "too-large"
			uniformError(rw, http.StatusRequestEntityTooLarge)
			return
		}
		if err != nil {
			blocked = true
			event.Stage = "protocol"
			if errors.Is(err, os.ErrDeadlineExceeded) {
				event.RuleID, event.RuleMsg = "body-timeout", "request body deadline exceeded"
				uniformError(rw, http.StatusRequestTimeout)
				return
			}
			uniformError(rw, http.StatusBadRequest)
			return
		}
		event.BytesIn = int64(len(body))
		preq.Body = body
	}

	if s.d.Gate.Handle(rw, r, &e.proxy, ip) {
		event.Stage = "access-gate"
		return
	}

	if verdict, info := s.d.Policy.Inspect(preq); verdict.Action != "allow" {
		event.Stage, event.RuleID, event.RuleMsg = verdict.Stage, verdict.Rule, verdict.Reason
		if info.Matched {
			event.RuleID = itoa(info.RuleID)
			// The reason is the rule's own message and names what it objected
			// to ("... restricted by policy (/expect/)"); replacing it with the
			// label left the operator with "protocol-violation" and nothing to
			// act on.
			if event.RuleMsg == "" {
				event.RuleMsg = info.Label
			}
		}
		if verdict.Action == "block" {
			blocked = true
			event.Action = "block"
			respondVerdict(rw, verdict)
			return
		}
		event.Action = "log"
	}

	route, done := s.applyRoutes(rw, r, e)
	if done {
		return
	}

	up := selectUpstream(e, r, rw)
	if route.Upstream != "" {
		up = e.upstreamFor(route.Upstream)
	}
	if up == nil {
		blocked = true
		event.Stage, event.RuleMsg = "upstream", "no healthy upstream"
		uniformError(rw, http.StatusBadGateway)
		return
	}
	// A logged verdict already names the stage that produced it; only a plain
	// forward is a route event.
	if event.Stage == "" {
		event.Stage = "route"
	}

	cleanInboundHeaders(r)
	applyHeaderOps(e.reqOps, r.Header)
	up.inFlight.Add(1)
	defer up.inFlight.Add(-1)

	// Cache the identity representation: the cache writer sits outside the gzip
	// writer so a hit writes its own body instead of a stale encoding. An
	// encoded hit is a variant of the one stored entry.
	gz := newGzipWriter(rw, r.Header.Get("Accept-Encoding"))
	var out http.ResponseWriter = gz
	var cw *cacheWriter
	if cacheable {
		key := cacheKeyOf
		enc, acceptable := negotiateEncoding(r.Header.Get("Accept-Encoding"))
		if !acceptable {
			blocked = true
			notAcceptable(rw, &event)
			return
		}
		// The cache stores identity and encodes per client, so ask the origin for
		// plain bytes: an encoded reply it sent on our own request would leave
		// the URL uncacheable for as long as the origin keeps compressing.
		r.Header.Set("Accept-Encoding", encIdentity)
		if entry, ok := e.cache.get(key); ok {
			e.serveCached(rw, key, entry, enc)
			return
		}
		cw = &cacheWriter{ResponseWriter: gz, key: key, cache: e.cache}
		out = cw
	}

	if e.waf != nil && e.waf.MaxResponse > 0 {
		cap := &capWriter{ResponseWriter: out, limit: e.waf.MaxResponse}
		cap.trip = func() {
			blocked = true
			// The wire may already carry a 200 the client will see truncated;
			// the log records what actually happened to the response.
			rw.status = http.StatusBadGateway
			event.Stage, event.RuleID = "response-cap", "too-large"
			event.RuleMsg = "upstream response exceeded the profile limit"
			if cw != nil {
				cw.skip = true
			}
		}
		out = cap
	}

	// A streamed upload is exempt from the whole-exchange timeout, as it is from
	// the body deadline: the bytes are the client's to send at its own pace. The
	// transport's response-header timeout still bounds the wait afterwards, and
	// the response ceiling still bounds the answer.
	timeout := e.timeout
	if skipBody {
		timeout = 0
	} else if route.Timeout > 0 {
		timeout = time.Duration(route.Timeout) * time.Second
	}
	ctx := r.Context()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	rv := &respVerdict{}
	ctx = context.WithValue(ctx, ctxUpstream, up)
	ctx = context.WithValue(ctx, ctxRespVerdict, rv)
	ctx = context.WithValue(ctx, ctxScheme, scheme)
	r = r.WithContext(ctx)
	e.rp.ServeHTTP(out, r)
	_ = gz.Close()
	if cw != nil {
		cw.finish()
	}
	// The response ceiling names its own outcome; leave that event alone.
	if rv.stage != "" && event.Stage != "response-cap" {
		event.Stage, event.RuleID, event.RuleMsg = rv.stage, rv.rule, rv.msg
		if rv.action != "" {
			event.Action = rv.action
		}
		blocked = rv.blocked
	}
}

// notAcceptable answers a client that accepts none of the body encodings the
// proxy can send.
func notAcceptable(w http.ResponseWriter, event *model.Event) {
	event.Stage, event.RuleID = "cache", "not-acceptable"
	w.Header().Set("Vary", "Accept-Encoding")
	uniformError(w, http.StatusNotAcceptable)
}

func respondVerdict(w http.ResponseWriter, v model.Verdict) {
	status := v.Status
	if status == 0 {
		status = http.StatusForbidden
	}
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "60")
	}
	uniformError(w, status)
}

func (s *Server) blackhole(w http.ResponseWriter, r *http.Request, host string, start time.Time) {
	// Unknown hosts and the bare apex are closed without a response so scanners
	// cannot fingerprint a default vhost. HTTP/2 has no hijack, so the fallback
	// still logs the event even though it must answer with a status code.
	event := model.Event{TS: start, Host: host, SrcIP: clientAddr(r).String(),
		Method: r.Method, Path: r.URL.Path, Stage: "unknown-host",
		RuleID: "blackhole", Action: "block", Status: 444, UA: r.UserAgent(), Sample: 1}
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			_ = conn.Close()
			s.record(event)
			return
		}
	}
	event.Status = http.StatusMisdirectedRequest
	s.record(event)
	// HTTP/3 has no connection to close and forbids the header; the stream is
	// the connection there, so only HTTP/1.1 gets it.
	if r.ProtoMajor < 3 {
		w.Header().Set("Connection", "close")
	}
	w.WriteHeader(http.StatusMisdirectedRequest)
}

func (s *Server) applyRoutes(w http.ResponseWriter, r *http.Request, e *edge) (model.Route, bool) {
	rt, target, ok := MatchRoute(r, e.routes)
	if !ok {
		return model.Route{}, false
	}
	switch rt.Kind {
	case model.RouteRedirect:
		status := rt.Status
		if status != http.StatusMovedPermanently && status != http.StatusTemporaryRedirect && status != http.StatusPermanentRedirect {
			status = http.StatusFound
		}
		http.Redirect(w, r, target, status)
		return rt, true
	case model.RouteAlias:
		r.URL.Path = target
		r.URL.RawPath = ""
	}
	return rt, false
}

// MatchRoute returns the first route whose matchers all agree, with the alias
// or redirect target resolved. Routes arrive ordered by priority.
func MatchRoute(r *http.Request, routes []model.Route) (model.Route, string, bool) {
	for _, rt := range routes {
		if rt.Method != "" && !strings.EqualFold(rt.Method, r.Method) {
			continue
		}
		if rt.Header != "" {
			name, want, ok := strings.Cut(rt.Header, ":")
			if !ok || !strings.EqualFold(strings.TrimSpace(r.Header.Get(strings.TrimSpace(name))), strings.TrimSpace(want)) {
				continue
			}
		}
		if rt.Query != "" && !strings.Contains(r.URL.RawQuery, strings.TrimSpace(rt.Query)) {
			continue
		}
		var re *regexp.Regexp
		if rt.Regex {
			var err error
			if re, err = regexp.Compile(rt.Match); err != nil || !re.MatchString(r.URL.Path) {
				continue
			}
		} else if !pathMatches(rt.Match, r.URL.Path) {
			continue
		}
		switch rt.Kind {
		case model.RouteRedirect:
			return rt, routeTarget(rt, re, r.URL.Path), true
		case model.RouteAlias:
			return rt, routeTarget(rt, re, r.URL.Path), true
		}
	}
	return model.Route{}, r.URL.Path, false
}

func routeTarget(rt model.Route, re *regexp.Regexp, path string) string {
	if re != nil {
		return re.ReplaceAllString(path, rt.Target)
	}
	if rt.Kind == model.RouteAlias {
		rest := strings.TrimPrefix(path, rt.Match)
		base := strings.TrimSuffix(rt.Target, "/")
		return base + "/" + strings.TrimPrefix(rest, "/")
	}
	return strings.ReplaceAll(rt.Target, "$path", path)
}

// RouteFor resolves a path as a GET without headers, so the request simulator
// can name the route a plain browser request would take.
func RouteFor(routes []model.Route, path string) (model.Route, string, bool) {
	u := &url.URL{Path: path}
	return MatchRoute(&http.Request{Method: http.MethodGet, URL: u, Header: http.Header{}}, routes)
}

func pathMatches(match, path string) bool {
	if match == "" || match == "/" {
		return true
	}
	if strings.HasSuffix(match, "*") {
		return strings.HasPrefix(path, strings.TrimSuffix(match, "*"))
	}
	return path == match || strings.HasPrefix(path, strings.TrimSuffix(match, "/")+"/")
}

// cleanInboundHeaders removes spoofable forwarding and override headers.
func cleanInboundHeaders(r *http.Request) {
	drop := []string{
		"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip",
		// Read by the client resolver from a trusted connector, then removed so a
		// request carried past the tunnel cannot name its own address upstream.
		"CF-Connecting-IP", "CF-Connecting-IPv4",
		"Forwarded", "X-Original-Url", "X-Rewrite-Url", "X-Http-Method-Override",
		"X-Forwarded-Server", "X-Forwarded-Port", "Proxy", "Proxy-Connection",
	}
	for _, h := range drop {
		r.Header.Del(h)
	}
}

// cleanPathSegments resolves "." and ".." segments, collapses duplicate
// slashes and treats a backslash as a separator, so the path the console shows,
// the WAF inspects and the upstream receives are the same. Browsers normalise
// before sending; an encoded or obfuscated dot segment is the only way one
// reaches this point.
func cleanPathSegments(p string) (string, bool) {
	if strings.ContainsRune(p, 0) {
		return "", false
	}
	if p == "" {
		return "/", true
	}
	// Anything that does not start with a slash is rooted below, so the path the
	// upstream receives is always absolute.
	if strings.HasPrefix(p, "/") && !strings.ContainsAny(p, "\\") &&
		!strings.Contains(p, ".") && !strings.Contains(p, "//") {
		return p, true
	}
	trailing := strings.HasSuffix(p, "/")
	p = strings.ReplaceAll(p, "\\", "/")
	var out []string
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	clean := "/" + strings.Join(out, "/")
	if trailing && clean != "/" {
		clean += "/"
	}
	return clean, true
}

// badRequestFraming rejects requests whose meaning depends on which hop reads
// them: two lengths, a length and a chunked body, a target in absolute form, or
// a header name that cannot be written back out. net/http rejects most of these
// itself; the pipeline is also reached by tests and future callers, so it
// refuses them on its own terms.
func badRequestFraming(r *http.Request) bool {
	if len(r.TransferEncoding) > 0 && r.ContentLength > 0 {
		return true
	}
	if len(r.Header.Values("Content-Length")) > 1 {
		return true
	}
	for name := range r.Header {
		if !validHeaderName(name) {
			return true
		}
	}
	if strings.HasPrefix(r.RequestURI, "http://") || strings.HasPrefix(r.RequestURI, "https://") {
		return true
	}
	// "OPTIONS *" addresses the server itself rather than a site behind it.
	if r.RequestURI == "*" {
		return true
	}
	if r.Method == http.MethodTrace || r.Method == "TRACK" || r.Method == http.MethodConnect {
		return true
	}
	// WebSocket is the one protocol switch an upstream can expect. Anything else
	// (notably h2c) would turn the proxy into a tunnel for a protocol it does not
	// inspect, so it is refused rather than forwarded.
	if upgrade := r.Header.Get("Upgrade"); upgrade != "" {
		if !strings.EqualFold(strings.TrimSpace(upgrade), "websocket") || r.Method != http.MethodGet {
			return true
		}
	}
	return false
}

// validHeaderName accepts the RFC 9110 token characters. net/http enforces the
// same rule when it parses a request; this keeps the check true for a request
// assembled in memory.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		octet := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		switch {
		case octet:
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// estimateBody reserves what the request will hold before its body is read: the
// declared length when there is one, the largest body the proxy will buffer when
// there is not. The reservation is settled against the real length afterwards.
func estimateBody(r *http.Request, hardBody int64) int64 {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return 0
	}
	if r.ContentLength > 0 {
		return min(r.ContentLength, hardBody)
	}
	return min(hardBody, 64<<10)
}

// bodySkipped reports whether this request's body is exempt from inspection.
// The prefix matches whole path segments, so "/api/assets" does not exempt
// "/api/assetsfoo". inLists is consulted only when an entry names lists.
func bodySkipped(entries []model.BodySkip, method, path string, inLists func([]int64) bool) bool {
	entry, trusted := SkipMatch(entries, method, path, inLists)
	return entry != nil && trusted
}

// SkipMatch returns the body-skip entry whose method and path match, and whether
// its trust lists admit the source. A nil entry means nothing matched; a non-nil
// entry with trusted false means the path is exempt only for the named sources,
// which the console shows so an upload that is still inspected says why.
func SkipMatch(entries []model.BodySkip, method, path string, inLists func([]int64) bool) (*model.BodySkip, bool) {
	var untrusted *model.BodySkip
	for i := range entries {
		e := &entries[i]
		if !strings.EqualFold(strings.TrimSpace(e.Method), method) {
			continue
		}
		if !pathPrefix(path, e.Prefix) {
			continue
		}
		if len(e.ListIDs) > 0 && (inLists == nil || !inLists(e.ListIDs)) {
			if untrusted == nil {
				untrusted = e
			}
			continue
		}
		return e, true
	}
	return untrusted, false
}

// pathPrefix matches a configured prefix as whole path segments. A trailing
// star is the wildcard shorthand route matchers already use, so
// "/api/assets/*" covers the same subtree as "/api/assets/" and reads the way
// an operator expects; the segment boundary still applies either way, so
// "/api/assets*" does not cover "/api/assetsfoo".
func pathPrefix(path, prefix string) bool {
	if prefix == "" || prefix == "/" {
		return false
	}
	if strings.HasSuffix(prefix, "*") {
		prefix = strings.TrimSuffix(prefix, "*")
		if prefix == "" || prefix == "/" {
			return false
		}
		if path == prefix || path == strings.TrimSuffix(prefix, "/") {
			return true
		}
		return strings.HasPrefix(path, strings.TrimSuffix(prefix, "/")+"/")
	}
	if path == prefix {
		return true
	}
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(path, prefix)
	}
	return strings.HasPrefix(path, prefix+"/")
}

// stallReader streams a body to the upstream and drops a client that stops
// sending. A transfer that keeps sending is never cut off, however long it
// takes, so this bounds silence rather than the upload.
//
// On HTTP/1 the deadline lives on the connection and is refreshed on every
// read. HTTP/2 has no per-request read deadline, so a watchdog closes the body
// instead, which unblocks the read that would otherwise wait forever.
type stallReader struct {
	r     io.ReadCloser
	rc    *http.ResponseController
	limit time.Duration

	mu      sync.Mutex
	n       int64
	last    time.Time
	stalled bool
	// useDeadline is decided once, when the body is wrapped.
	useDeadline bool

	once sync.Once
	done chan struct{}
}

func newStallReader(r io.ReadCloser, limit time.Duration, rc *http.ResponseController) *stallReader {
	s := &stallReader{r: r, rc: rc, limit: limit, last: time.Now(), done: make(chan struct{})}
	if limit <= 0 {
		return s
	}
	if rc.SetReadDeadline(time.Now().Add(limit)) == nil {
		s.useDeadline = true
	} else {
		go s.watch()
	}
	return s
}

// watch closes the body when no byte has arrived for the whole guard window,
// for the protocols whose connection deadline cannot be set.
func (s *stallReader) watch() {
	t := time.NewTicker(max(s.limit/4, 10*time.Millisecond))
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-t.C:
			s.mu.Lock()
			fire := !s.stalled && now.Sub(s.last) >= s.limit
			if fire {
				s.stalled = true
			}
			s.mu.Unlock()
			if fire {
				_ = s.r.Close()
				return
			}
		}
	}
}

func (s *stallReader) Read(p []byte) (int, error) {
	if s.useDeadline {
		_ = s.rc.SetReadDeadline(time.Now().Add(s.limit))
	}
	n, err := s.r.Read(p)
	if n > 0 {
		s.mu.Lock()
		s.last = time.Now()
		s.n += int64(n)
		s.mu.Unlock()
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		s.mu.Lock()
		s.stalled = true
		s.mu.Unlock()
	}
	return n, err
}

func (s *stallReader) Close() error {
	s.once.Do(func() { close(s.done) })
	return s.r.Close()
}

func (s *stallReader) bytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

func (s *stallReader) didStall() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stalled
}

// errBudgetFull is returned when a body with no declared length grows past what
// the buffer budget can hold. The reservation only covers the declared length,
// or 64 KiB when there is none, so the read has to charge for the rest.
var errBudgetFull = errors.New("request body exceeded the buffered byte budget")

// readBody buffers a request body up to limit bytes. credit is what the budget
// already reserved for this body; anything past it is charged as it is read, so
// a chunked body cannot allocate more than the budget allows.
func readBody(r *http.Request, limit, credit int64, charge func(int64) bool) ([]byte, bool, error) {
	if r.Body == nil || r.Method == http.MethodGet || r.Method == http.MethodHead {
		_ = r.Body.Close()
		r.Body = http.NoBody
		return nil, false, nil
	}
	if r.ContentLength > limit {
		return nil, true, nil
	}
	var buf bytes.Buffer
	chunk := make([]byte, 32<<10)
	var read int64
	for {
		n, rerr := r.Body.Read(chunk)
		if n > 0 {
			read += int64(n)
			if read > limit {
				_ = r.Body.Close()
				return nil, true, nil
			}
			claimed := min(int64(n), credit)
			credit -= claimed
			if extra := int64(n) - claimed; extra > 0 && charge != nil && !charge(extra) {
				_ = r.Body.Close()
				return nil, false, errBudgetFull
			}
			_, _ = buf.Write(chunk[:n])
		}
		if rerr != nil {
			_ = r.Body.Close()
			if errors.Is(rerr, io.EOF) {
				break
			}
			return nil, false, rerr
		}
	}
	body := buf.Bytes()
	r.Body = io.NopCloser(bytes.NewReader(body))
	// A buffered body is sent with its real length, not as a chunked stream.
	r.TransferEncoding = nil
	// A buffered body can be replayed by the retry transport.
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	r.ContentLength = int64(len(body))
	return body, false, nil
}

func clientAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

func itoa(v int) string {
	if v == 0 {
		return ""
	}
	const digits = "0123456789"
	var b [12]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = digits[v%10]
		v /= 10
	}
	return string(b[i:])
}
