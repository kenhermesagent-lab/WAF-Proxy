package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/botguard"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/policy"
)

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := normalizeHost(r.Host)
	e := s.lookup(host)

	rw := &responseWriter{ResponseWriter: w, strict: true, requestID: newRequestID()}
	if e == nil {
		s.blackhole(w, r, host, start)
		return
	}
	if e.proxy.Fingerprint == "minimal" {
		rw.strict = false
	}

	ip := clientAddr(r)
	loc := s.d.Geo.Lookup(ip)
	event := model.Event{
		TS: start, ProxyID: &e.proxy.ID, Host: host, SrcIP: ip.String(),
		Country: loc.Country, ASN: loc.ASN, Lat: loc.Lat, Lon: loc.Lon,
		Method: r.Method, Path: r.URL.Path, UA: r.UserAgent(), Sample: 1,
	}
	blocked := false
	defer func() {
		event.Status = rw.Status()
		event.BytesOut = rw.Size()
		event.LatencyMS = time.Since(start).Milliseconds()
		if blocked {
			event.Action = "block"
		} else if event.Action == "" {
			event.Action = "allow"
		}
		s.record(event)
		var b int64
		if blocked {
			b = 1
		}
		s.d.Metrics.Count(e.proxy.ID, 1, b, event.BytesIn, event.BytesOut)
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
		if verdict.Stage == "feed" && s.d.Bots.Verified(r) {
			blocked = false
		} else if s.d.Bots.HandleChallenge(rw, r, &e.proxy, ip.String()) {
			return
		} else {
			blocked = false
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

	if r.URL.Path == botguard.SolvePath {
		if s.d.Bots.HandleChallenge(rw, r, &e.proxy, ip.String()) {
			event.Stage, event.Action = "bot-challenge", "challenge"
			return
		}
	}
	if e.proxy.BotLevel != "" && e.proxy.BotLevel != "off" &&
		botguard.BrowserLike(r) && !s.d.Bots.Verified(r) {
		if s.d.Bots.HandleChallenge(rw, r, &e.proxy, ip.String()) {
			event.Stage, event.Action = "bot-challenge", "challenge"
			blocked = true
			return
		}
	}

	body, tooLarge, err := readBody(r, s.hardBody)
	if tooLarge {
		blocked = true
		event.Stage, event.RuleID = "body-limit", "too-large"
		uniformError(rw, http.StatusRequestEntityTooLarge)
		return
	}
	if err != nil {
		blocked = true
		event.Stage = "protocol"
		uniformError(rw, http.StatusBadRequest)
		return
	}
	event.BytesIn = int64(len(body))
	preq.Body = body

	if s.d.Gate.Handle(rw, r, &e.proxy, ip) {
		event.Stage = "access-gate"
		return
	}

	if verdict, info := s.d.Policy.Inspect(preq); verdict.Action != "allow" {
		event.Stage, event.RuleID, event.RuleMsg = verdict.Stage, verdict.Rule, verdict.Reason
		if info.Matched {
			event.RuleID = itoa(info.RuleID)
			event.RuleMsg = info.Label
		}
		if verdict.Action == "block" {
			blocked = true
			event.Action = "block"
			respondVerdict(rw, verdict)
			return
		}
		event.Action = "log"
	}

	if done := s.applyRoutes(rw, r, e); done {
		return
	}

	up := pick(e.ups, &e.rr)
	if up == nil {
		blocked = true
		event.Stage, event.RuleMsg = "upstream", "no healthy upstream"
		uniformError(rw, http.StatusBadGateway)
		return
	}
	event.Stage = "route"

	cleanInboundHeaders(r)
	up.inFlight.Add(1)
	defer up.inFlight.Add(-1)

	// Cache the uncompressed representation: the cache writer sits outside the
	// gzip writer so a cache hit is written without a stale Content-Encoding.
	gz := newGzipWriter(rw, r.Header.Get("Accept-Encoding"))
	var out http.ResponseWriter = gz
	var cw *cacheWriter
	if cacheableRequest(r) {
		key := cacheKey(r)
		if entry, ok := e.cache.get(key); ok {
			for k, vals := range entry.header {
				rw.Header()[k] = append([]string(nil), vals...)
			}
			rw.Header().Del("Content-Length")
			rw.WriteHeader(entry.status)
			_, _ = rw.Write(entry.body)
			return
		}
		cw = &cacheWriter{ResponseWriter: gz, key: key, cache: e.cache}
		out = cw
	}

	ctx := context.WithValue(r.Context(), ctxUpstream, up)
	r = r.WithContext(ctx)
	e.rp.ServeHTTP(out, r)
	_ = gz.Close()
	if cw != nil {
		cw.finish()
	}
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
	// cannot fingerprint a default vhost.
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			_ = conn.Close()
			s.record(model.Event{TS: start, Host: host, SrcIP: clientAddr(r).String(),
				Method: r.Method, Path: r.URL.Path, Stage: "unknown-host",
				RuleID: "blackhole", Action: "block", Status: 444, UA: r.UserAgent(), Sample: 1})
			return
		}
	}
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusMisdirectedRequest)
}

func (s *Server) applyRoutes(w http.ResponseWriter, r *http.Request, e *edge) bool {
	for _, rt := range e.routes {
		if !pathMatches(rt.Match, r.URL.Path) {
			continue
		}
		switch rt.Kind {
		case model.RouteRedirect:
			target := strings.ReplaceAll(rt.Target, "$path", r.URL.Path)
			http.Redirect(w, r, target, http.StatusFound)
			return true
		case model.RouteAlias:
			rest := strings.TrimPrefix(r.URL.Path, rt.Match)
			base := strings.TrimSuffix(rt.Target, "/")
			r.URL.Path = base + "/" + strings.TrimPrefix(rest, "/")
			r.URL.RawPath = ""
			return false
		}
	}
	return false
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
		"Forwarded", "X-Original-Url", "X-Rewrite-Url", "X-Http-Method-Override",
		"X-Forwarded-Server", "X-Forwarded-Port", "Proxy", "Proxy-Connection",
	}
	for _, h := range drop {
		r.Header.Del(h)
	}
}

func badRequestFraming(r *http.Request) bool {
	if len(r.TransferEncoding) > 0 && r.ContentLength > 0 {
		return true
	}
	if len(r.Header.Values("Content-Length")) > 1 {
		return true
	}
	if strings.HasPrefix(r.RequestURI, "http://") || strings.HasPrefix(r.RequestURI, "https://") {
		return true
	}
	if r.Method == http.MethodTrace || r.Method == "TRACK" || r.Method == http.MethodConnect {
		return true
	}
	return false
}

func readBody(r *http.Request, limit int64) ([]byte, bool, error) {
	if r.Body == nil || r.Method == http.MethodGet || r.Method == http.MethodHead {
		_ = r.Body.Close()
		r.Body = http.NoBody
		return nil, false, nil
	}
	if r.ContentLength > limit {
		return nil, true, nil
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	_ = r.Body.Close()
	if err != nil {
		return nil, false, err
	}
	if int64(len(buf)) > limit {
		return nil, true, nil
	}
	r.Body = io.NopCloser(bytes.NewReader(buf))
	r.ContentLength = int64(len(buf))
	return buf, false, nil
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
