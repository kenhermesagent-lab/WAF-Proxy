package scan

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/scantrust"
)

const maxDetailBytes = 2048

// secretHeaders are the headers whose values are replaced by their name before
// anything is stored.
var secretHeaders = map[string]bool{
	"Authorization":       true,
	"Cookie":              true,
	"Proxy-Authorization": true,
	"X-Api-Key":           true,
}

// secretParams are query parameters that carry a credential.
var secretParams = map[string]bool{
	"token": true, "key": true, "api_key": true, "apikey": true,
	"secret": true, "password": true, "pass": true, "sig": true,
	"signature": true, "auth": true,
}

// RedactRequest renders a probe as one storable block. Every credential value
// becomes its name, because evidence outlives the run that produced it.
func RedactRequest(p Probe) string {
	var b strings.Builder
	b.WriteString(p.Method + " " + p.Path)
	if p.Query != "" {
		b.WriteString("?" + redactQuery(p.Query))
	}
	names := make([]string, 0, len(p.Header))
	for name := range p.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		value := strings.Join(p.Header.Values(name), ", ")
		// The scan token is a credential for the ban exemption, so it is
		// redacted like any other secret even though the runner adds it only
		// at send time.
		if secretHeaders[http.CanonicalHeaderKey(name)] || strings.EqualFold(name, scantrust.Header) {
			value = "REDACTED"
		}
		b.WriteString("\n" + name + ": " + value)
	}
	if b.Len() > maxDetailBytes {
		return b.String()[:maxDetailBytes]
	}
	return b.String()
}

func redactQuery(raw string) string {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return "REDACTED"
	}
	for name := range values {
		if secretParams[strings.ToLower(name)] {
			values.Set(name, "REDACTED")
		}
	}
	return values.Encode()
}
