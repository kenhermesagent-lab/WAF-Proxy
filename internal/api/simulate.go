package api

import (
	"bytes"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/policy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/proxy"
)

const (
	simDefaultIP      = "203.0.113.10"
	simMaxHeaders     = 32
	simMaxHeaderBytes = 8 << 10
)

type simulateBody struct {
	ProxyID  int64             `json:"proxy_id"`
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Query    string            `json:"query"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body"`
	ClientIP string            `json:"client_ip"`
}

// simulate replays one request through the real pipeline without side effects.
// It answers for a configured site only: a simulation is not an event, and
// nothing here is audited or persisted.
func (s *Server) simulate(w http.ResponseWriter, r *http.Request) {
	var in simulateBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if s.policy == nil {
		writeError(w, http.StatusServiceUnavailable, "the policy engine is not running")
		return
	}
	if in.ProxyID <= 0 {
		writeError(w, http.StatusBadRequest, "proxy_id is required")
		return
	}
	proxies, err := s.db(r).ListProxies()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	var site *model.Proxy
	for i := range proxies {
		if proxies[i].ID == in.ProxyID {
			site = &proxies[i]
			break
		}
	}
	if site == nil {
		writeError(w, http.StatusNotFound, "unknown proxy")
		return
	}
	if len(in.Headers) > simMaxHeaders {
		writeError(w, http.StatusBadRequest, "too many headers")
		return
	}
	total := 0
	for k, v := range in.Headers {
		total += len(k) + len(v)
	}
	if total > simMaxHeaderBytes {
		writeError(w, http.StatusBadRequest, "headers are too large")
		return
	}

	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = http.MethodGet
	}
	path := in.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		writeError(w, http.StatusBadRequest, "path must start with /")
		return
	}
	u, err := url.Parse(path)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid path")
		return
	}
	// A browser encodes a pasted query before sending it; without this a space
	// in the query field trips 920100 for a request line no client can send.
	u.RawQuery = in.Query
	if vals, err := url.ParseQuery(in.Query); err == nil {
		u.RawQuery = vals.Encode()
	}

	addrText := in.ClientIP
	if addrText == "" {
		addrText = simDefaultIP
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(addrText))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid client_ip")
		return
	}
	addr = addr.Unmap()

	body := []byte(in.Body)
	truncated := false
	if limit := s.policyFor(r).MaxBody(site); int64(len(body)) > limit {
		body, truncated = body[:limit], true
	}
	hreq := &http.Request{
		Method: method, URL: u, Host: site.Hostname, Proto: "HTTP/1.1",
		ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{}, RequestURI: u.RequestURI(),
	}
	for k, v := range in.Headers {
		hreq.Header.Set(k, v)
	}
	if len(body) > 0 {
		hreq.Body = io.NopCloser(bytes.NewReader(body))
		hreq.ContentLength = int64(len(body))
	} else {
		hreq.Body = http.NoBody
	}
	loc := geoip.Location{}
	if s.geo != nil {
		loc = s.geo.Lookup(addr)
	}

	res := s.policyFor(r).Simulate(policy.SimRequest{
		Proxy: site, Host: site.Hostname, Method: method, Path: u.Path, Query: u.RawQuery,
		UA: hreq.Header.Get("User-Agent"), Addr: addr, Loc: loc, Body: body, HTTP: hreq,
	})
	res.Truncated = truncated

	if res.Verdict.Action != "block" && res.Verdict.Action != "ban" {
		routes, err := s.db(r).ListRoutes(site.ID)
		if err == nil {
			if route, routePath, ok := proxy.RouteFor(routes, u.Path); ok {
				if route.Kind == model.RouteRedirect {
					res.Route = "redirect to " + strings.ReplaceAll(route.Target, "$path", u.Path)
				} else {
					res.Route = "alias " + route.Match + " to " + routePath
				}
			}
		}
		ups, err := s.db(r).ListUpstreams(site.ID)
		if err == nil {
			for _, up := range ups {
				if up.Enabled && up.URL != "" {
					res.Upstream = up.URL
					break
				}
			}
		}
		stage := policy.SimStage{Stage: "route", Verdict: "allow", Reason: res.Route}
		res.Stages = append(res.Stages, stage)
		if res.Upstream == "" && res.Route == "" {
			res.Notes = append(res.Notes, "no enabled upstream or route is configured for this proxy")
		}
	}

	writeJSON(w, http.StatusOK, res)
}
