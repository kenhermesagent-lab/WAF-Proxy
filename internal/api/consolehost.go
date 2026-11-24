package api

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ConsoleHosts refuses admin-console requests addressed to a name the console
// does not answer to. A browser on any page can be made to reach this port, and
// the session cookie is sent with it, so a Host the operator never configured is
// refused: that is what keeps a DNS-rebinding page from reading the console
// through the victim's browser.
//
// An address literal is always accepted, because the console is reached by
// address on a host network and that cannot be rebound. Names come from the
// console host and the operator's allowlist.
func ConsoleHosts(hosts []string, next http.Handler) http.Handler {
	allowed := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			allowed[h] = true
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !consoleHostAllowed(r.Host, allowed) {
			http.Error(w, "admin console does not answer this Host", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func consoleHostAllowed(host string, allowed map[string]bool) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	return allowed[host]
}
