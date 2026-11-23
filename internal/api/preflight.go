package api

import (
	"fmt"
	"net/http"
	"net/netip"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// preflightLimit bounds the work a single preview does. The log keeps far more,
// but an operator wants "what would this have done to the recent traffic", not
// a full-table scan on every keystroke.
const preflightLimit = 500

type preflightSample struct {
	TS     time.Time `json:"ts"`
	SrcIP  string    `json:"src_ip"`
	Host   string    `json:"host"`
	Method string    `json:"method"`
	Path   string    `json:"path"`
	Stage  string    `json:"stage"`
	Action string    `json:"action"`
}

type preflightResult struct {
	Kind      string            `json:"kind"`
	Value     string            `json:"value"`
	Hours     int               `json:"hours"`
	Scanned   int               `json:"scanned"`
	Matched   int               `json:"matched"`
	Allowed   int               `json:"allowed"`
	Blocked   int               `json:"blocked"`
	Addresses int               `json:"addresses"`
	Hosts     []string          `json:"hosts"`
	Samples   []preflightSample `json:"samples"`
	Notes     []string          `json:"notes"`
}

// preflightPolicy answers "what would this policy do to the traffic already in
// the log?" before the operator saves it. It is read-only and uses the same
// matchers the request path uses.
func (s *Server) preflightPolicy(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Kind    string `json:"kind"`
		Value   string `json:"value"`
		Scope   string `json:"scope"`
		ProxyID *int64 `json:"proxy_id"`
		Hours   int    `json:"hours"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if !policyKinds[in.Kind] {
		writeError(w, http.StatusBadRequest, "unknown policy kind")
		return
	}
	if strings.TrimSpace(in.Value) == "" {
		writeError(w, http.StatusBadRequest, "value is required")
		return
	}
	if msg := validatePolicyValue(in.Kind, in.Value); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	hours := in.Hours
	if hours <= 0 || hours > 168 {
		hours = 24
	}
	out := preflightResult{
		Kind: in.Kind, Value: in.Value, Hours: hours,
		Hosts: []string{}, Samples: []preflightSample{}, Notes: []string{},
	}
	if in.Kind == "rate_limit" {
		out.Notes = append(out.Notes, "Rate limits depend on live connection state and cannot be replayed against the log.")
		writeJSON(w, http.StatusOK, out)
		return
	}

	filter := store.EventFilter{From: time.Now().Add(-time.Duration(hours) * time.Hour), Limit: preflightLimit}
	if in.Scope == "proxy" && in.ProxyID != nil {
		filter.ProxyID = in.ProxyID
	}
	events, _, err := s.db(r).QueryEvents(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}

	match := policyEventMatcher(in.Kind, in.Value)
	addresses := map[string]bool{}
	hosts := map[string]bool{}
	out.Scanned = len(events)
	for _, e := range events {
		if !match(e) {
			continue
		}
		out.Matched++
		if e.Action == "allow" {
			out.Allowed++
		} else {
			out.Blocked++
		}
		if e.SrcIP != "" {
			addresses[e.SrcIP] = true
		}
		if e.Host != "" {
			hosts[e.Host] = true
		}
		if len(out.Samples) < 5 {
			out.Samples = append(out.Samples, preflightSample{
				TS: e.TS, SrcIP: e.SrcIP, Host: e.Host, Method: e.Method,
				Path: e.Path, Stage: e.Stage, Action: e.Action,
			})
		}
	}
	out.Addresses = len(addresses)
	for h := range hosts {
		out.Hosts = append(out.Hosts, h)
	}
	sort.Strings(out.Hosts)
	if len(out.Hosts) > 5 {
		out.Hosts = out.Hosts[:5]
	}
	if out.Scanned == preflightLimit {
		out.Notes = append(out.Notes, fmt.Sprintf("Only the newest %d events in the window were evaluated.", preflightLimit))
	}
	writeJSON(w, http.StatusOK, out)
}

// policyEventMatcher returns the predicate a policy of this kind and value
// applies to a recorded event.
func policyEventMatcher(kind, value string) func(model.Event) bool {
	switch kind {
	case model.PolicyIPWhitelist, model.PolicyIPBlacklist:
		var prefixes []netip.Prefix
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if p, err := netip.ParsePrefix(part); err == nil {
				prefixes = append(prefixes, p)
				continue
			}
			if a, err := netip.ParseAddr(part); err == nil {
				prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
			}
		}
		return func(e model.Event) bool {
			addr, err := netip.ParseAddr(e.SrcIP)
			if err != nil {
				return false
			}
			for _, p := range prefixes {
				if p.Contains(addr) {
					return true
				}
			}
			return false
		}
	case model.PolicyCountryWhitelist, model.PolicyCountryBlacklist:
		set := map[string]bool{}
		for _, part := range strings.Split(value, ",") {
			if c := strings.ToUpper(strings.TrimSpace(part)); c != "" {
				set[c] = true
			}
		}
		return func(e model.Event) bool { return set[strings.ToUpper(e.Country)] }
	case model.PolicyASNBlock:
		set := map[int]bool{}
		for _, part := range strings.Split(value, ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
				set[n] = true
			}
		}
		return func(e model.Event) bool { return e.ASN != 0 && set[e.ASN] }
	case model.PolicyDecoy:
		var decoys []string
		for _, part := range strings.Split(value, ",") {
			if p := canonicalEventPath(part); p != "" {
				decoys = append(decoys, p)
			}
		}
		return func(e model.Event) bool {
			p := canonicalEventPath(e.Path)
			for _, d := range decoys {
				if p == d || strings.HasPrefix(p, d+"/") {
					return true
				}
			}
			return false
		}
	}
	return func(model.Event) bool { return false }
}

// canonicalEventPath mirrors the policy engine's decoy comparison, because
// "/./.env", "//.env" and "/x/../.env" all reach the same file upstream.
func canonicalEventPath(p string) string {
	if strings.TrimSpace(p) == "" {
		return ""
	}
	return strings.ToLower(path.Clean("/" + p))
}
