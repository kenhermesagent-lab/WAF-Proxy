// Package safepath normalises user-supplied redirect targets.
//
// The gate, the bot challenge and any future interstitial page all take a
// "next" parameter from an unauthenticated request and send the browser there
// after success. Keeping one implementation means the open-redirect defences
// cannot drift apart between callers.
package safepath

import (
	"net/url"
	"strings"
)

// Next returns a same-origin path that is safe to use as a redirect target.
// Anything absolute, protocol-relative, containing a backslash (which browsers
// normalise to a slash) or control characters collapses to "/".
func Next(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	// Browsers treat "\" as "/" in http(s) URLs, so "/\evil.example" would
	// become the protocol-relative "//evil.example" after the redirect.
	// Control characters are refused because they could split the header.
	if strings.ContainsAny(next, "\\\r\n\t") {
		return "/"
	}
	if u, err := url.Parse(next); err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return next
}
