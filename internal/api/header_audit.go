package api

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// headerCheck is one profile setting compared with what the application
// already sends.
type headerCheck struct {
	Setting string `json:"setting"`
	Header  string `json:"header"`
	Backend string `json:"backend"`
	Profile string `json:"profile"`
	Verdict string `json:"verdict"` // strong | covered | compatible | gap | at-risk
	Advice  string `json:"advice"`
}

type headerAudit struct {
	Proxy      string            `json:"proxy"`
	Upstream   string            `json:"upstream"`
	Status     int               `json:"status"`
	SelfSigned bool              `json:"self_signed"`
	Headers    map[string]string `json:"headers"`
	Checks     []headerCheck     `json:"checks"`
	Summary    []string          `json:"summary"`
}

// auditProtectionHeaders fetches the first enabled upstream of a proxy and
// compares its security headers with the protection profile, so an operator
// can see whether the proxy setting would weaken or duplicate what the
// application already does.
func (s *Server) auditProtectionHeaders(w http.ResponseWriter, r *http.Request) {
	proxyID, err := strconv.ParseInt(r.URL.Query().Get("proxy_id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "proxy_id is required")
		return
	}
	p, err := s.st.GetProxy(proxyID)
	if err != nil {
		writeError(w, http.StatusNotFound, "proxy not found")
		return
	}
	prof := s.protectionProfileFor(p, r.URL.Query().Get("profile_id"))
	if prof == nil {
		writeError(w, http.StatusBadRequest, "this proxy has no protection profile; choose one first")
		return
	}
	ups, err := s.st.ListUpstreams(proxyID)
	if err != nil || len(ups) == 0 {
		writeError(w, http.StatusBadRequest, "this proxy has no upstream to check")
		return
	}
	target, err := probeTarget(ups[0].URL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hdr, status, insecure, err := fetchHeaders(target, p.Hostname)
	if err != nil {
		writeError(w, http.StatusBadGateway, "could not reach the backend: "+err.Error())
		return
	}
	out := headerAudit{
		Proxy: p.Hostname, Upstream: target.String(), Status: status,
		SelfSigned: insecure, Headers: map[string]string{},
	}
	for _, name := range []string{"x-frame-options", "content-security-policy", "strict-transport-security",
		"x-content-type-options", "referrer-policy"} {
		if v := hdr.Get(name); v != "" {
			out.Headers[name] = v
		}
	}
	out.Checks = assessHeaders(hdr, prof)
	for _, c := range out.Checks {
		if c.Verdict == "at-risk" || c.Verdict == "gap" {
			out.Summary = append(out.Summary, c.Advice)
		}
	}
	if len(out.Summary) == 0 {
		out.Summary = append(out.Summary, "The application already covers these headers; the profile settings are compatible.")
	}
	writeJSON(w, http.StatusOK, out)
}

// protectionProfileFor resolves the profile to compare: the one the caller
// selected, else the proxy's inherited profile, else its access profile.
func (s *Server) protectionProfileFor(p *model.Proxy, override string) *model.ProtectionProfile {
	if override != "" {
		if id, err := strconv.ParseInt(override, 10, 64); err == nil {
			if prof, err := s.st.GetProtectionProfile(id); err == nil {
				return prof
			}
		}
	}
	if p.ProtectionProfileID != nil {
		if prof, err := s.st.GetProtectionProfile(*p.ProtectionProfileID); err == nil {
			return prof
		}
	}
	if p.AccessProfileID != nil {
		if ap, err := s.st.GetAccessProfile(*p.AccessProfileID); err == nil && ap.ProtectionProfileID != nil {
			if prof, err := s.st.GetProtectionProfile(*ap.ProtectionProfileID); err == nil {
				return prof
			}
		}
	}
	return nil
}

// probeTarget turns an upstream URL into the root URL the audit requests.
func probeTarget(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("the upstream URL is not valid")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("the upstream must use http or https")
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/"}, nil
}

// fetchHeaders requests the backend root as the proxied hostname, so a virtual
// host answers with its real headers. A self-signed certificate is retried once
// without verification: many home backends use one, and an audit that cannot
// see the headers cannot warn about them.
func fetchHeaders(target *url.URL, hostname string) (http.Header, int, bool, error) {
	get := func(insecure bool) (*http.Response, error) {
		// No environment proxy: the audit must reach the operator's backend,
		// not an HTTP_PROXY set for the service.
		tr := &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure},
			DisableKeepAlives: true,
		}
		client := &http.Client{
			Timeout:   6 * time.Second,
			Transport: tr,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		req, err := http.NewRequest(http.MethodGet, target.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Host = hostname
		req.Header.Set("User-Agent", "wafproxy-header-audit/1.0")
		return client.Do(req)
	}
	resp, err := get(false)
	insecure := false
	if err != nil && target.Scheme == "https" && strings.Contains(strings.ToLower(err.Error()), "certificate") {
		resp, err = get(true)
		insecure = err == nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	defer resp.Body.Close()
	return resp.Header, resp.StatusCode, insecure, nil
}

// assessHeaders compares the application's headers with the profile.
func assessHeaders(h http.Header, p *model.ProtectionProfile) []headerCheck {
	xfo := strings.ToUpper(strings.TrimSpace(h.Get("X-Frame-Options")))
	csp := strings.TrimSpace(h.Get("Content-Security-Policy"))
	hsts := strings.TrimSpace(h.Get("Strict-Transport-Security"))
	nosniff := strings.EqualFold(strings.TrimSpace(h.Get("X-Content-Type-Options")), "nosniff")
	referrer := strings.TrimSpace(h.Get("Referrer-Policy"))

	frameStrong := xfo == "DENY" || xfo == "SAMEORIGIN" || frameAncestors(csp) != ""
	checks := []headerCheck{
		{
			Setting: "frame_options", Header: "X-Frame-Options / CSP frame-ancestors",
			Backend: joinNonEmpty(xfo, frameAncestors(csp)),
			Profile: emptyAs(p.FrameOptions, "off"),
			Verdict: frameVerdict(xfo, frameStrong, p.FrameOptions),
			Advice:  frameAdvice(frameStrong, p.FrameOptions),
		},
		{
			Setting: "hsts", Header: "Strict-Transport-Security",
			Backend: emptyAs(hsts, "not sent"),
			Profile: hstsProfile(p),
			Verdict: hstsVerdict(hsts, p.HSTS),
			Advice:  hstsAdvice(hsts, p.HSTS),
		},
		{
			Setting: "csp", Header: "Content-Security-Policy",
			Backend: emptyAs(csp, "not sent"),
			Profile: emptyAs(p.CSP, "not set"),
			Verdict: cspVerdict(csp, p.CSP),
			Advice:  cspAdvice(csp, p.CSP),
		},
		{
			Setting: "nosniff", Header: "X-Content-Type-Options",
			Backend: boolText(nosniff, "nosniff", "not sent"),
			Profile: boolText(p.NoSniff, "nosniff", "off"),
			Verdict: tri(boolText(nosniff, "strong", ""), boolText(p.NoSniff, "strong", "")),
			Advice:  nosniffAdvice(nosniff, p.NoSniff),
		},
		{
			Setting: "referrer_policy", Header: "Referrer-Policy",
			Backend: emptyAs(referrer, "not sent"),
			Profile: emptyAs(p.ReferrerPolicy, "not set"),
			Verdict: tri(boolText(referrer != "" && !strings.EqualFold(referrer, "unsafe-url"), "strong", ""),
				boolText(p.ReferrerPolicy != "", "strong", "")),
			Advice: referrerAdvice(referrer, p.ReferrerPolicy),
		},
	}
	return checks
}

func frameAncestors(csp string) string {
	lower := strings.ToLower(csp)
	i := strings.Index(lower, "frame-ancestors")
	if i < 0 {
		return ""
	}
	rest := csp[i+len("frame-ancestors"):]
	if j := strings.IndexByte(rest, ';'); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

func frameVerdict(xfo string, strong bool, setting string) string {
	switch {
	case setting == "off" && strong:
		return "at-risk"
	case setting == "off":
		return "gap"
	case xfo == "DENY" && setting == "sameorigin":
		return "at-risk"
	case strong:
		return "compatible"
	}
	return "covered"
}

func frameAdvice(strong bool, setting string) string {
	switch {
	case setting == "off" && strong:
		return "The application already blocks framing, but frame_options=off deletes its X-Frame-Options header. Keep sameorigin or deny in the profile (or leave frame_options alone)."
	case setting == "off":
		return "Neither the application nor the profile blocks framing. Set frame_options to sameorigin or deny."
	case setting == "sameorigin":
		return "The application sends DENY, but this profile replaces it with SAMEORIGIN, which allows same-origin framing. Use DENY to keep the stronger policy."
	case strong:
		return "The application and the profile both restrict framing; the profile value wins and is equally strong."
	}
	return "The profile supplies framing protection the application does not send."
}

func hstsProfile(p *model.ProtectionProfile) string {
	if !p.HSTS {
		return "off"
	}
	if p.HSTSSubdomains {
		return "max-age=31536000; includeSubDomains"
	}
	return "max-age=31536000"
}

func hstsVerdict(hsts string, on bool) string {
	if on {
		return "compatible"
	}
	if hsts != "" {
		return "covered"
	}
	return "gap"
}

func hstsAdvice(hsts string, on bool) string {
	switch {
	case on:
		return "The profile sends a one-year HSTS policy on every HTTPS response, replacing any longer application value. That is the usual choice for a public site."
	case hsts != "":
		return "The application already sends HSTS, so leaving the profile off does not weaken it."
	}
	return "Neither the application nor the profile sends HSTS. Enable it in the profile."
}

func cspVerdict(backend, setting string) string {
	switch {
	case setting != "":
		return "compatible"
	case backend != "":
		return "covered"
	}
	return "gap"
}

func cspAdvice(backend, setting string) string {
	switch {
	case setting != "":
		return "The profile sends its own CSP, which replaces the application's header. Make sure the profile policy allows everything the app needs."
	case backend != "":
		return "The application already sends a CSP; leaving the profile's CSP empty keeps it intact."
	}
	return "No CSP is sent. Consider a restrictive policy in the profile."
}

func nosniffAdvice(backend, setting bool) string {
	switch {
	case setting:
		return "The profile sends nosniff on every response."
	case backend:
		return "The application already sends nosniff; the profile does not override it."
	}
	return "Neither side sends nosniff. Enable it in the profile."
}

func referrerAdvice(backend, setting string) string {
	switch {
	case setting != "":
		return "The profile sets Referrer-Policy, replacing any application value."
	case backend != "":
		return "The application already sets Referrer-Policy; the profile leaves it alone."
	}
	return "No Referrer-Policy is sent. Set one in the profile."
}

// tri returns "compatible" when both sides set the header, "covered" when only
// the application does, and "gap" when neither does.
func tri(backend, profile string) string {
	switch {
	case profile == "strong":
		return "compatible"
	case backend == "strong":
		return "covered"
	}
	return "gap"
}

func joinNonEmpty(parts ...string) string {
	out := []string{}
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return "not sent"
	}
	return strings.Join(out, " · ")
}

func emptyAs(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func boolText(v bool, yes, no string) string {
	if v {
		return yes
	}
	return no
}
