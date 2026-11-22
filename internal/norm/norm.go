// Package norm finds request encodings that different layers decode
// differently: repeated parameter names and values that only reveal their
// payload on a second decode.
package norm

import (
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// Rule IDs reported for these findings.
const (
	RuleDuplicate     = 900120
	RuleDoubleEncoded = 900121
)

const (
	// maxFindings keeps one hostile request from filling an event row.
	maxFindings = 3
	// maxValue caps what is copied into a finding, because the values are
	// attacker-supplied and land in the event log.
	maxValue = 40
)

// Finding is one normalization problem in a request.
type Finding struct {
	Kind      string `json:"kind"`
	Source    string `json:"source"`
	Parameter string `json:"parameter"`
	First     string `json:"first,omitempty"`
	Second    string `json:"second,omitempty"`
}

// Inspect reports findings for the query string and, when it is a form, the
// body. Body bytes are the ones already read and limited by the caller.
func Inspect(r *http.Request, body []byte) []Finding {
	if r == nil {
		return nil
	}
	out := appendPairs(nil, r.URL.RawQuery, "query")
	if len(body) == 0 {
		return out
	}
	ct := r.Header.Get("Content-Type")
	if mt, _, err := mime.ParseMediaType(ct); err != nil || mt != "application/x-www-form-urlencoded" {
		return out
	}
	return appendPairs(out, string(body), "body")
}

// appendPairs walks the raw pairs rather than the parsed form: parsing has
// already collapsed repeated names into a map, which hides how many there were.
func appendPairs(out []Finding, raw, source string) []Finding {
	if raw == "" || len(out) >= maxFindings {
		return out
	}
	values := map[string]map[string]bool{}
	var names []string
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		rawName, rawValue, _ := strings.Cut(pair, "=")
		name, err := url.QueryUnescape(rawName)
		if err != nil || name == "" {
			continue
		}
		value, err := url.QueryUnescape(rawValue)
		if err != nil {
			continue
		}
		if again, err := url.QueryUnescape(value); err == nil && again != value {
			out = append(out, Finding{Kind: "double-encoded", Source: source, Parameter: trim(name),
				First: trim(value), Second: trim(again)})
			if len(out) >= maxFindings {
				return out
			}
		}
		seen, ok := values[name]
		if !ok {
			seen = map[string]bool{}
			values[name] = seen
			names = append(names, name)
		}
		seen[value] = true
	}
	for _, name := range names {
		// Repeating a name with the same value is how ordinary forms submit
		// checkboxes and multi-selects.
		if len(values[name]) > 1 {
			out = append(out, Finding{Kind: "duplicate-parameter", Source: source, Parameter: trim(name)})
			if len(out) >= maxFindings {
				return out
			}
		}
	}
	return out
}

func trim(s string) string {
	if len(s) <= maxValue {
		return s
	}
	return s[:maxValue] + "…"
}
