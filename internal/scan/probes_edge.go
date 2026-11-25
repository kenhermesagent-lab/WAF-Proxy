package scan

import (
	"net/http"
	"strings"
)

// edgeClasses are the protocol and edge probes: shapes a site should refuse
// before they reach the application. Every one is read-only, and the raw ones
// are only ever sent to the published path.
func edgeClasses(probePath, host string) []ProbeClass {
	return []ProbeClass{
		getClass(StageEdge, "method-trace", probePath, http.MethodTrace),
		hostClass(StageEdge, "host-upper-case", probePath, strings.ToUpper(host)),
		hostClass(StageEdge, "host-trailing-dot", probePath, host+"."),
		headerClass(StageEdge, "forwarded-host", probePath, "X-Forwarded-Host", "evil.example", host),
		headerClass(StageEdge, "original-url", probePath, "X-Original-URL", "/admin", "/"),
		pathClass(StageEdge, "null-byte-path", probePath, "%00"),
		pathClass(StageEdge, "traversal-encoded", probePath, "/..%2f..%2fetc%2fpasswd"),
		pathClass(StageEdge, "traversal-double-encoded", probePath, "/%252e%252e%252fetc%252fpasswd"),
		pathClass(StageEdge, "semicolon-parameters", probePath, ";id=1"),
		pathClass(StageEdge, "overlong-utf8", probePath, "/%c0%bcscript%c0%bealert(1)%c0%bc%2fscript%c0%be"),
		bodyClass(StageEdge, "json-depth", probePath, "application/json", `{"id":1}`, deepJSON(64)),
		bodyClass(StageEdge, "multipart-boundary", probePath, "multipart/form-data; boundary=XX",
			multipartBody("id", "1"),
			"--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x\"\r\n\r\nx\r\n--XX--\r\n"),
		rawClass(StageEdge, "framing-cl-te", probePath, http.MethodPost, framingCLTE(probePath, host), true,
			"a desynchronised connection must not carry application traffic, so the upstream half was skipped"),
		rawClass(StageEdge, "framing-te-cl", probePath, http.MethodPost, framingTECL(probePath, host), true,
			"a desynchronised connection must not carry application traffic, so the upstream half was skipped"),
		rawClass(StageEdge, "absolute-form", probePath, http.MethodGet, absoluteForm(probePath, host), false,
			"net/http cannot build an absolute request target, so the upstream half was skipped"),
		rawClass(StageEdge, "http-1.0", probePath, http.MethodGet, http10(probePath, host), false,
			"net/http cannot build an HTTP/1.0 request, so the upstream half was skipped"),
	}
}

// multipartBody is a well-formed form-data body with one harmless field, the
// control every multipart probe is measured against.
func multipartBody(name, value string) string {
	return "--XX\r\nContent-Disposition: form-data; name=\"" + name + "\"\r\n\r\n" + value + "\r\n--XX--\r\n"
}

// deepJSON nests an object far enough that a parser with a depth ceiling has to
// decide something. The value is a harmless word.
func deepJSON(depth int) string {
	var b strings.Builder
	for i := 0; i < depth; i++ {
		b.WriteString(`{"a":`)
	}
	b.WriteString(`"x"`)
	b.WriteString(strings.Repeat("}", depth))
	return b.String()
}
