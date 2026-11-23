// Package openapi renders an OpenAPI document from the admin routes that are
// registered in internal/api/server.go.
package openapi

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

var routePattern = regexp.MustCompile(`m\.HandleFunc\("([A-Z]+) ([^"]+)", (.+)\)`)
var handlerPattern = regexp.MustCompile(`s\.(\w+)(?:\(|$)`)

type route struct {
	method  string
	path    string
	handler string
	authed  bool
	tag     string
	params  []string
}

// Generate renders the document for the routes found in src.
// operationID derives a stable, unique id from the method and path; handler
// names repeat (every guarded route records "authed") and validators reject that.
func operationID(method, path string) string {
	id := strings.ToLower(method)
	for _, seg := range strings.Split(path, "/") {
		for _, word := range strings.FieldsFunc(seg, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r)
		}) {
			id += strings.ToUpper(word[:1]) + word[1:]
		}
	}
	return id
}

func Generate(src []byte, version string) ([]byte, error) {
	routes, err := parse(string(src))
	if err != nil {
		return nil, err
	}
	return render(routes, version), nil
}

func parse(src string) ([]route, error) {
	var routes []route
	for _, m := range routePattern.FindAllStringSubmatch(src, -1) {
		r := route{method: m[1], path: m[2], authed: strings.Contains(m[3], "authed(")}
		call := handlerPattern.FindStringSubmatch(m[3])
		if call == nil {
			continue
		}
		r.handler = call[1]
		segs := strings.Split(strings.TrimPrefix(r.path, "/"), "/")
		if len(segs) > 1 && segs[0] == "api" {
			r.tag = segs[1]
		} else if len(segs) > 0 {
			r.tag = segs[0]
		}
		for _, part := range segs {
			if strings.HasPrefix(part, "{") {
				r.params = append(r.params, strings.Trim(part, "{}"))
			}
		}
		routes = append(routes, r)
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("no routes found")
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].path == routes[j].path {
			return routes[i].method < routes[j].method
		}
		return routes[i].path < routes[j].path
	})
	return routes, nil
}

func humanize(name string) string {
	var b strings.Builder
	for i, r := range name {
		if unicode.IsUpper(r) && i > 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

const schemaBlock = `    Proxy:
      type: object
      properties:
        id: {type: integer}
        hostname: {type: string}
        enabled: {type: boolean}
        upstreams:
          type: array
          items: {$ref: '#/components/schemas/Upstream'}
        tls_min_version: {type: string, enum: ["1.2", "1.3"]}
        upstream_timeout_s: {type: integer}
        retries: {type: integer}
    Upstream:
      type: object
      properties:
        id: {type: integer}
        url: {type: string}
        weight: {type: integer}
        max_conns: {type: integer}
    Ban:
      type: object
      properties:
        id: {type: integer}
        cidr: {type: string, description: IP or CIDR}
        reason: {type: string}
        source: {type: string}
        permanent: {type: boolean}
        expires_at: {type: string, format: date-time}
        created_at: {type: string, format: date-time}
    BanRequest:
      type: object
      required: [cidr]
      properties:
        cidr: {type: string, example: 203.0.113.7/32}
        reason: {type: string}
        permanent: {type: boolean}
    Cert:
      type: object
      properties:
        id: {type: integer}
        domains: {type: string}
        status: {type: string}
        source: {type: string, enum: [acme, uploaded, internal]}
        challenge: {type: string, enum: [dns-01, http-01, tls-alpn-01]}
        renew_mode: {type: string}
        expires_at: {type: string, format: date-time}
        last_error: {type: string}
    CertRequest:
      type: object
      required: [domains]
      properties:
        domains: {type: string, description: Comma-separated names}
        challenge: {type: string, enum: [dns-01, http-01, tls-alpn-01]}
        provider: {type: string}
        renew_mode: {type: string}
    CertUpload:
      type: object
      required: [cert_pem, key_pem]
      properties:
        cert_pem: {type: string}
        key_pem: {type: string}
    CertInternal:
      type: object
      required: [domains]
      properties:
        domains: {type: string}
        common_name: {type: string}
    Alert:
      type: object
      properties:
        id: {type: integer}
        channel: {type: string}
        kind: {type: string}
        dedupe: {type: string}
        payload: {type: string}
        state: {type: string}
        attempts: {type: integer}
        created_at: {type: string, format: date-time}
        sent_at: {type: string, format: date-time}
    NotificationSettings:
      type: object
      additionalProperties: {type: string}
      description: Stored notification settings; responses mask secret values.
    NotificationTest:
      type: object
      required: [channel]
      properties:
        channel: {type: string, enum: [telegram, email, webhook]}
    AnomalyConfig:
      type: object
      properties:
        enabled: {type: boolean}
        egress_mb: {type: integer, minimum: 1}
        egress_factor: {type: number, minimum: 1.1}
        rate_rps: {type: integer, minimum: 1}
        rate_factor: {type: number, minimum: 1.1}
        auth_burst: {type: integer, minimum: 1}
    AnomalyEvent:
      type: object
      properties:
        id: {type: integer}
        kind: {type: string, enum: [egress_spike, rate_spike, auth_burst]}
        proxy_id: {type: integer}
        proxy_host: {type: string}
        value: {type: number}
        baseline: {type: number}
        detail: {type: string}
        state: {type: string, enum: [open, acknowledged]}
        created_at: {type: string, format: date-time}
    AnomalyReport:
      type: object
      properties:
        config: {$ref: '#/components/schemas/AnomalyConfig'}
        events:
          type: array
          items: {$ref: '#/components/schemas/AnomalyEvent'}
    NotificationReport:
      type: object
      properties:
        settings: {$ref: '#/components/schemas/NotificationSettings'}
        channels:
          type: object
          additionalProperties: {type: boolean}
        recent:
          type: array
          items:
            allOf:
              - $ref: '#/components/schemas/Alert'
              - type: object
                properties:
                  class: {type: string}
                  muted: {type: boolean}
        event_kinds:
          type: array
          items:
            type: object
            properties:
              kind: {type: string}
              label: {type: string}
    Status:
      type: object
      properties:
        status: {type: string}
`

// shape describes the bodies a route accepts and returns, by API group.
type shape struct {
	request  string
	response string
	array    bool
	text     bool
}

func shapeFor(r route) shape {
	single := len(r.params) > 0
	switch r.tag {
	case "proxies":
		return shape{request: "Proxy", response: "Proxy", array: !single}
	case "bans":
		return shape{request: "BanRequest", response: "Ban", array: !single}
	case "certs":
		switch {
		case strings.HasSuffix(r.path, "/upload"):
			return shape{request: "CertUpload", response: "Cert"}
		case strings.HasSuffix(r.path, "/internal"):
			return shape{request: "CertInternal", response: "Cert"}
		case strings.HasSuffix(r.path, "/internal/root"):
			return shape{text: true}
		case strings.HasSuffix(r.path, "/renew"), strings.HasSuffix(r.path, "/revoke"):
			return shape{response: "Status"}
		case single:
			return shape{request: "CertRequest", response: "Cert"}
		default:
			return shape{request: "CertRequest", response: "Cert", array: true}
		}
	case "notifications":
		switch {
		case strings.HasSuffix(r.path, "/test"):
			return shape{request: "NotificationTest", response: "Status"}
		case r.method == "GET":
			return shape{response: "NotificationReport"}
		default:
			return shape{request: "NotificationSettings", response: "Status"}
		}
	case "anomaly":
		switch {
		case strings.HasSuffix(r.path, "/settings"):
			return shape{request: "AnomalyConfig", response: "Status"}
		case strings.HasSuffix(r.path, "/ack"):
			return shape{response: "Status"}
		default:
			return shape{response: "AnomalyReport"}
		}
	}
	return shape{}
}

func render(routes []route, version string) []byte {
	var b strings.Builder
	b.WriteString("# Generated by tools/openapi; do not edit by hand.\n")
	b.WriteString("openapi: 3.0.3\ninfo:\n  title: WAF-Proxy admin API\n  version: \"" + version + "\"\n")
	b.WriteString("  description: |\n    Routes registered by the admin console. Every `/api` route except setup,\n    login, health and version requires the session cookie and, for mutations,\n    the `X-CSRF-Token` header.\n")
	b.WriteString("servers:\n  - url: http://127.0.0.1:8080\n    description: Admin console (WAFPROXY_LISTEN_GUI)\n")
	b.WriteString("components:\n  securitySchemes:\n    sessionCookie:\n      type: apiKey\n      in: cookie\n      name: __wfp_sid\n  schemas:\n")
	b.WriteString(schemaBlock)
	b.WriteString("paths:\n")
	lastPath := ""
	for _, r := range routes {
		if r.path != lastPath {
			b.WriteString("  " + r.path + ":\n")
			lastPath = r.path
		}
		sh := shapeFor(r)
		b.WriteString("    " + strings.ToLower(r.method) + ":\n")
		b.WriteString("      operationId: " + operationID(r.method, r.path) + "\n")
		b.WriteString("      tags: [" + r.tag + "]\n")
		b.WriteString("      summary: " + strings.Title(humanize(r.handler)) + "\n")
		if r.authed {
			b.WriteString("      security:\n        - sessionCookie: []\n")
		} else {
			b.WriteString("      security: []\n")
		}
		if len(r.params) > 0 {
			b.WriteString("      parameters:\n")
			for _, p := range r.params {
				// Row ids are numeric; names and addresses such as {ip} are not.
				kind := "string"
				if p == "id" || strings.HasSuffix(p, "_id") {
					kind = "integer"
				}
				b.WriteString("        - name: " + p + "\n          in: path\n          required: true\n          schema: {type: " + kind + "}\n")
			}
		}
		mutating := r.method == "POST" || r.method == "PUT" || r.method == "PATCH"
		if mutating && sh.request != "" {
			b.WriteString("      requestBody:\n        required: true\n        content:\n          application/json:\n            schema: {$ref: '#/components/schemas/" + sh.request + "'}\n")
		}
		b.WriteString("      responses:\n        \"200\":\n")
		switch {
		case sh.text:
			b.WriteString("          description: Internal CA root certificate in PEM form\n          content:\n            application/x-pem-file:\n              schema: {type: string}\n")
		case sh.response != "" && sh.array:
			b.WriteString("          description: Success\n          content:\n            application/json:\n              schema:\n                type: array\n                items: {$ref: '#/components/schemas/" + sh.response + "'}\n")
		case sh.response != "":
			b.WriteString("          description: Success\n          content:\n            application/json:\n              schema: {$ref: '#/components/schemas/" + sh.response + "'}\n")
		default:
			b.WriteString("          description: Success\n")
		}
		if r.authed {
			b.WriteString("        \"401\":\n          description: Missing or expired session\n")
		}
		b.WriteString("        \"400\":\n          description: Invalid request\n")
	}
	return []byte(b.String())
}
