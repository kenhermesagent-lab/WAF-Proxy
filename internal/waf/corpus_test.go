package waf

// The bypass corpus from the security review, pinned as a regression test: a CRS
// or bundle update can lose a rule without touching this repository.
//
// Seventy of the 76 probes are decided here; HTTP/0.9 and TRACE by the listener
// and the pipeline, and duplicate-CL/TE.CL/CL.TE by framing, both in
// internal/proxy. The review's PROTO-10 sent two ordinary headers rather than an
// injection, so it is not asserted. The control rows keep the path rule from
// turning ordinary URLs into false positives.
//
// The follow-up review's probes are here too, including the gzip and UTF-16
// bodies, which live in transportCorpus because their wire form is not a string.
// Its Host-header probe is not asserted here: a Host that names no site is
// refused by the routing that picks the site, which internal/proxy covers.

import (
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

type corpusCase struct {
	ID        string
	Category  string
	Technique string
	Method    string
	Target    string
	Headers   map[string]string
	Body      string
	// WantBlocked is the verdict the shipped profile has to produce.
	WantBlocked bool
	// Rule is the rule expected to name the verdict, when the case pins one.
	Rule int
}

const (
	formCT = "application/x-www-form-urlencoded"
	jsonCT = "application/json"
	xmlCT  = "application/xml"
	multCT = "multipart/form-data; boundary=XX"
)

var bypassCorpus = []corpusCase{
	// ---- SQL injection ---------------------------------------------------
	{"SQLI-01", "SQLi", "plain query parameter", "GET", `/?id=1%27%20OR%201%3D1--`, nil, "", true, 0},
	{"SQLI-02", "SQLi", "mixed-case UNION SELECT", "GET", `/?id=1%27%20UnIoN%20SeLeCt%20password%20FrOm%20users--`, nil, "", true, 0},
	{"SQLI-03", "SQLi", "double URL encoding", "GET", `/?id=%2527%2520OR%25201%253D1--`, nil, "", true, 0},
	{"SQLI-04", "SQLi", "MySQL inline comments", "GET", `/?id=1%27%2F*!UNION*%2F%2F*!SELECT*%2Fpassword%2F*!FROM*%2Fusers--`, nil, "", true, 0},
	{"SQLI-05", "SQLi", "MySQL version comment", "GET", `/?id=1%27%2F*!50000UNION*%2F%2F*!50000SELECT*%2F1,2,3--`, nil, "", true, 0},
	{"SQLI-06", "SQLi", "null byte before OR", "GET", `/?id=1%27%00%20OR%201%3D1--`, nil, "", true, 0},
	{"SQLI-07", "SQLi", "tab and newline for spaces", "GET", `/?id=1%27%09UNION%0ASELECT%0D1,2,3--`, nil, "", true, 0},
	{"SQLI-08", "SQLi", "vertical tab as whitespace", "GET", `/?id=1%27%0bOR%0b1%3D1--`, nil, "", true, 0},
	{"SQLI-09", "SQLi", "comment for space", "GET", `/?id=1%27%2F**%2FOR%2F**%2F1%3D1--`, nil, "", true, 0},
	{"SQLI-10", "SQLi", "numeric tautology", "GET", `/?id=1%20OR%201%3D1`, nil, "", true, 0},
	{"SQLI-11", "SQLi", "LIKE tautology", "GET", `/?id=1%27%20OR%201%20LIKE%201--`, nil, "", true, 0},
	{"SQLI-12", "SQLi", "string tautology", "GET", `/?id=1%27%20OR%20%27a%27%3D%27a`, nil, "", true, 0},
	{"SQLI-13", "SQLi", "Oracle concat", "GET", `/?id=1%27%7C%7C%271`, nil, "", true, 0},
	{"SQLI-14", "SQLi", "stacked query", "GET", `/?id=1%27%3B%20DROP%20TABLE%20users--`, nil, "", true, 0},
	{"SQLI-15", "SQLi", "URL-encoded POST body", "POST", `/login`, map[string]string{"Content-Type": formCT}, `user=1%27%20OR%201%3D1--&pass=x`, true, 0},
	{"SQLI-16", "SQLi", "raw POST body", "POST", `/login`, map[string]string{"Content-Type": formCT}, `user=1' OR 1=1--&pass=x`, true, 0},
	{"SQLI-17", "SQLi", "JSON body", "POST", `/api/query`, map[string]string{"Content-Type": jsonCT}, `{"id":"1' UNION SELECT password FROM users--"}`, true, 0},
	{"SQLI-18", "SQLi", "XML body", "POST", `/api/data`, map[string]string{"Content-Type": xmlCT}, `<data><id>1' UNION SELECT password FROM users--</id></data>`, true, 0},
	{"SQLI-19", "SQLi", "HTTP parameter pollution", "GET", `/?id=1%27%20UNION&id=SELECT%20password%20FROM%20users--`, nil, "", true, 0},
	{"SQLI-20", "SQLi", "payload split across parameters", "GET", `/?id=1%27%2F*&q=*%2FUNION%20SELECT%201,2,3--`, nil, "", true, 0},
	{"SQLI-21", "SQLi", "array parameter", "GET", `/?id[]=1%27%20OR%201%3D1--`, nil, "", true, 0},
	{"SQLI-22", "SQLi", "semicolon matrix parameter in path", "GET", `/item;id=1%27%20OR%201%3D1--`, nil, "", true, 900111},
	{"SQLI-23", "SQLi", "path segment", "GET", `/search/1%27%20OR%201%3D1--/x`, nil, "", true, 900111},
	{"SQLI-24", "SQLi", "User-Agent header", "GET", `/`, map[string]string{"User-Agent": `1' OR 1=1--`}, "", true, 0},
	{"SQLI-25", "SQLi", "Referer header", "GET", `/`, map[string]string{"Referer": `http://x/?id=1' OR 1=1--`}, "", true, 0},
	// X-Forwarded-For is deliberately allowed through inspection: the proxy
	// overwrites it with the socket peer before the WAF and before the upstream,
	// so the payload cannot reach anything. Asserting the allow pins that the
	// rewrite, not the rule set, is what neutralises it.
	{"SQLI-26", "SQLi", "X-Forwarded-For header", "GET", `/`, map[string]string{"X-Forwarded-For": `1' OR 1=1--`}, "", false, 0},
	{"SQLI-27", "SQLi", "Cookie value", "GET", `/`, map[string]string{"Cookie": `session=1' OR 1=1--`}, "", true, 0},
	{"SQLI-28", "SQLi", "PUT method body", "PUT", `/api/query`, map[string]string{"Content-Type": formCT}, `id=1' OR 1=1--`, true, 0},
	{"SQLI-29", "SQLi", "PATCH method body", "PATCH", `/api/query`, map[string]string{"Content-Type": formCT}, `id=1' OR 1=1--`, true, 0},
	{"SQLI-30", "SQLi", "de-chunked body", "POST", `/login`, map[string]string{"Content-Type": formCT}, `user=1' OR 1=1--&pass=x`, true, 0},
	{"SQLI-31", "SQLi", "multipart form field", "POST", `/upload`, map[string]string{"Content-Type": multCT},
		"--XX\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n1' OR 1=1--\r\n--XX--\r\n", true, 0},
	{"SQLI-32", "SQLi", "charset=ibm037 content type", "POST", `/login`, map[string]string{"Content-Type": formCT + "; charset=ibm037"}, `id=1' OR 1=1--`, true, 0},
	{"SQLI-33", "SQLi", "content-type confusion", "POST", `/api/query`, map[string]string{"Content-Type": jsonCT}, `id=1' OR 1=1--`, true, 0},
	{"SQLI-34", "SQLi", "text/plain body", "POST", `/api/query`, map[string]string{"Content-Type": "text/plain"}, `id=1' OR 1=1--`, true, 0},
	{"SQLI-35", "SQLi", "payload in the 90th of 100 parameters", "GET",
		`/?p0=x&p1=x&p2=x&p3=x&p4=x&p5=x&p6=x&p7=x&p8=x&p9=x&p10=x&p11=x&p12=x&p13=x&p14=x&p15=x&p16=x&p17=x&p18=x&p19=x&p20=x&p21=x&p22=x&p23=x&p24=x&p25=x&p26=x&p27=x&p28=x&p29=x&p30=x&p31=x&p32=x&p33=x&p34=x&p35=x&p36=x&p37=x&p38=x&p39=x&p40=x&p41=x&p42=x&p43=x&p44=x&p45=x&p46=x&p47=x&p48=x&p49=x&p50=x&p51=x&p52=x&p53=x&p54=x&p55=x&p56=x&p57=x&p58=x&p59=x&p60=x&p61=x&p62=x&p63=x&p64=x&p65=x&p66=x&p67=x&p68=x&p69=x&p70=x&p71=x&p72=x&p73=x&p74=x&p75=x&p76=x&p77=x&p78=x&p79=x&p80=x&p81=x&p82=x&p83=x&p84=x&p85=x&p86=x&p87=x&p88=x&p89=x&id=1%27%20OR%201%3D1--`,
		nil, "", true, 0},

	// A payload the application decodes a second time still arrives as "%27"
	// after the one decode the path gets, so the rule decodes it too.
	{"SQLI-36", "SQLi", "double-encoded path SQLi", "GET", `/search/1%2527%2520OR%25201%253D1--`, nil, "", true, 900111},

	// ---- XSS -------------------------------------------------------------
	{"XSS-01", "XSS", "plain script tag", "GET", `/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E`, nil, "", true, 0},
	{"XSS-02", "XSS", "mixed case", "GET", `/?q=%3CScRiPt%3Ealert(1)%3C%2FScRiPt%3E`, nil, "", true, 0},
	{"XSS-03", "XSS", "img onerror", "GET", `/?q=%3Cimg%20src%3Dx%20oNerRor%3Dalert(1)%3E`, nil, "", true, 0},
	{"XSS-04", "XSS", "svg onload", "GET", `/?q=%3Csvg%2Fonload%3Dalert(1)%3E`, nil, "", true, 0},
	{"XSS-05", "XSS", "body onpageshow", "GET", `/?q=%3Cbody%20onpageshow%3Dalert(1)%3E`, nil, "", true, 0},
	{"XSS-06", "XSS", "marquee onstart", "GET", `/?q=%3Cmarquee%20onstart%3Dalert(1)%3E`, nil, "", true, 0},
	{"XSS-07", "XSS", "javascript: URI", "GET", `/?q=%3Ca%20href%3Djavascript%3Aalert(1)%3Eclick%3C%2Fa%3E`, nil, "", true, 0},
	{"XSS-08", "XSS", "template literal call", "GET", `/?q=%3Cscript%3Ealert%601%60%3C%2Fscript%3E`, nil, "", true, 0},
	{"XSS-09", "XSS", "unicode escape in script", "GET", `/?q=%3Cscript%3Eal%5Cu0065rt(1)%3C%2Fscript%3E`, nil, "", true, 0},
	{"XSS-10", "XSS", "HTML-entity encoded handler", "GET",
		`/?q=%3Cimg%20src%3Dx%20onerror%3D%26%2397%3B%26%23108%3B%26%23101%3B%26%23114%3B%26%23116%3B(1)%3E`, nil, "", true, 0},
	{"XSS-11", "XSS", "double-encoded tag", "GET", `/?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E`, nil, "", true, 0},
	{"XSS-12", "XSS", "null byte inside tag", "GET", `/?q=%3Cscri%00pt%3Ealert(1)%3C%2Fscript%3E`, nil, "", true, 0},
	{"XSS-13", "XSS", "details/ontoggle", "GET", `/?q=%3Cdetails%20open%20ontoggle%3Dalert(1)%3E`, nil, "", true, 0},
	{"XSS-14", "XSS", "Referer header", "GET", `/`, map[string]string{"Referer": `http://x/?q=<script>alert(1)</script>`}, "", true, 0},
	{"XSS-15", "XSS", "User-Agent header", "GET", `/`, map[string]string{"User-Agent": `<script>alert(1)</script>`}, "", true, 0},
	{"XSS-16", "XSS", "JSON body", "POST", `/api/comment`, map[string]string{"Content-Type": jsonCT}, `{"comment":"<script>alert(1)</script>"}`, true, 0},
	{"XSS-17", "XSS", "multipart field", "POST", `/comment`, map[string]string{"Content-Type": multCT},
		"--XX\r\nContent-Disposition: form-data; name=\"c\"\r\n\r\n<script>alert(1)</script>\r\n--XX--\r\n", true, 0},
	{"XSS-18", "XSS", "path segment", "GET", `/user/%3Csvg%2Fonload%3Dalert(1)%3E`, nil, "", true, 0},
	{"XSS-19", "XSS", "multipart filename", "POST", `/upload`, map[string]string{"Content-Type": multCT},
		"--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"<script>alert(1)</script>\"\r\n\r\nx\r\n--XX--\r\n", true, 900114},

	// ---- path traversal --------------------------------------------------
	{"PATH-01", "Path traversal", "plain ../", "GET", `/?file=../../etc/passwd`, nil, "", true, 0},
	{"PATH-02", "Path traversal", "URL-encoded", "GET", `/?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd`, nil, "", true, 0},
	{"PATH-03", "Path traversal", "backslash", "GET", `/?file=..%5c..%5cwindows%5cwin.ini`, nil, "", true, 0},
	{"PATH-04", "Path traversal", "in the request path", "GET", `/static/../../etc/passwd`, nil, "", true, 0},
	{"PATH-05", "Path traversal", "multipart filename", "POST", `/upload`, map[string]string{"Content-Type": multCT},
		"--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"../../etc/passwd\"\r\n\r\nx\r\n--XX--\r\n", true, 0},

	// ---- RCE -------------------------------------------------------------
	{"RCE-01", "RCE", "Log4Shell in User-Agent", "GET", `/`, map[string]string{"User-Agent": `${jndi:ldap://127.0.0.1:1389/a}`}, "", true, 0},
	{"RCE-02", "RCE", "Log4Shell in parameter", "GET", `/?x=%24%7Bjndi%3Aldap%3A%2F%2F127.0.0.1%3A1389%2Fa%7D`, nil, "", true, 0},
	{"RCE-03", "RCE", "Shellshock in User-Agent", "GET", `/`, map[string]string{"User-Agent": `() { :; }; /bin/bash -c id`}, "", true, 0},
	{"RCE-04", "RCE", "Spring4Shell classloader", "GET", `/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=x`, nil, "", true, 0},
	{"RCE-05", "RCE", "PHP code in body", "POST", `/x.php`, map[string]string{"Content-Type": formCT}, `a=<?php system($_GET[c]); ?>`, true, 0},

	// ---- XXE / SSRF ------------------------------------------------------
	{"XXE-01", "XXE", "external entity in an XML body", "POST", `/api/data`, map[string]string{"Content-Type": xmlCT},
		`<?xml version="1.0"?><!DOCTYPE d [<!ENTITY e SYSTEM "file:///etc/passwd">]><d>&e;</d>`, true, 900112},
	{"XXE-02", "XXE", "external DTD", "POST", `/api/data`, map[string]string{"Content-Type": xmlCT},
		`<?xml version="1.0"?><!DOCTYPE d SYSTEM "http://169.254.169.254/x.dtd"><d/>`, true, 900112},
	{"XXE-03", "XXE", "parameter entity", "POST", `/api/data`, map[string]string{"Content-Type": xmlCT},
		`<?xml version="1.0"?><!DOCTYPE d [<!ENTITY % p SYSTEM "http://169.254.169.254/a.dtd">%p;]><d/>`, true, 900112},
	// The declaration is refused whatever the declared type: a body labelled
	// JSON that carries an XML entity would otherwise walk past the XML
	// processor entirely.
	{"XXE-04", "XXE", "entity under a JSON content type", "POST", `/api/data`, map[string]string{"Content-Type": jsonCT},
		`<!DOCTYPE d [<!ENTITY e SYSTEM "file:///etc/passwd">]>`, true, 900112},
	// An internal entity is a legitimate, self-contained XML feature.
	{"XXE-05", "XXE", "internal entity stays allowed", "POST", `/api/data`, map[string]string{"Content-Type": xmlCT},
		`<?xml version="1.0"?><!DOCTYPE d [<!ENTITY e "text">]><d>&e;</d>`, false, 0},
	{"SSRF-01", "SSRF", "cloud metadata URL", "GET", `/?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F`, nil, "", true, 0},
	{"SSRF-03", "SSRF", "metadata URL in the path", "GET", `/fetch/http://169.254.169.254/latest/meta-data/`, nil, "", true, 900113},
	{"SSRF-02", "SSRF", "file:// scheme", "GET", `/?url=file%3A%2F%2F%2Fetc%2Fpasswd`, nil, "", true, 0},

	// ---- protocol and encoding, as the engine sees them ------------------
	// PROTO-05: the proxy de-chunks before inspection, so the body arrives whole.
	{"PROTO-05", "Protocol", "chunked body, assembled before inspection", "POST", `/login`,
		map[string]string{"Content-Type": formCT}, `id=1' UNION SELECT password FROM users--`, true, 0},
	{"PROTO-06", "Protocol", "8 KiB User-Agent", "GET", `/?id=1`,
		map[string]string{"User-Agent": strings.Repeat("A", 8000) + `1' OR 1=1--`}, "", true, 0},
	{"PROTO-07", "Protocol", "overlong UTF-8 encoding of <", "GET", `/?q=%c0%bcscript%c0%bealert(1)%c0%bc%2fscript%c0%be`, nil, "", true, 0},
	{"PROTO-09", "Protocol", "body over the inspection limit", "POST", `/login`, map[string]string{"Content-Type": formCT},
		"pad=" + strings.Repeat("A", 200000) + "&id=1' OR 1=1--", true, 200004},

	// ---- Round two: parser and path evasions -------------------------------
	{"R2-04", "Encoding", "double-encoded path SQLi", "GET", `/search/1%2527%2520OR%25201%253D1--`, nil, "", true, 900111},
	// The wire form is %u0027, which Go refuses to parse as a URL; one level of
	// percent-decoding puts the same escape in front of the path rule.
	{"R2-07", "Encoding", "IIS %u0027 escape in a path", "GET", `/search/1%25u0027%20OR%201%3D1--`, nil, "", true, 0},
	{"R2-08", "Encoding", "overlong UTF-8 traversal", "GET", `/static/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd`, nil, "", true, 0},
	{"R2-09", "SQLi", "UNION nested in JSON objects", "POST", `/api/query`, map[string]string{"Content-Type": jsonCT}, `{"id":{"a":{"b":{"c":{"d":"1' UNION SELECT password FROM users--"}}}}}`, true, 0},
	{"R2-10", "SQLi", "unicode-escaped SQLi in JSON", "POST", `/api/query`, map[string]string{"Content-Type": jsonCT}, `{"id":"1\u0027 OR 1=1--"}`, true, 0},
	{"R2-11", "SQLi", "SQLi in a multipart filename", "POST", `/upload`, map[string]string{"Content-Type": multCT}, "--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"1' OR 1=1--\"\r\n\r\nx\r\n--XX--\r\n", true, 0},
	{"R2-12", "XSS", "XSS in a multipart filename", "POST", `/upload`, map[string]string{"Content-Type": multCT}, "--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"<script>alert(1)</script>\"\r\n\r\nx\r\n--XX--\r\n", true, 900114},
	{"R2-13", "XXE", "declaration split across lines", "POST", `/api/data`, map[string]string{"Content-Type": xmlCT}, "<?xml version=\"1.0\"?>\n<!DOCTYPE d [\n<!ENTITY e\n  SYSTEM \"file:///etc/passwd\"\n>]><d>&e;</d>", true, 900112},
	{"R2-14", "SQLi", "Oracle concat in a path", "GET", `/x/1'%7C%7C'1`, nil, "", true, 0},
	{"R2-15", "SQLi", "AND SLEEP in a path", "GET", `/x/1'%20AND%20SLEEP(5)%20AND%20'1'%3D'1`, nil, "", true, 0},
	{"R2-16", "SQLi", "path SQLi past 8 KiB", "GET", "/search/" + strings.Repeat("a", 8200) + "/1'%20OR%201%3D1--", nil, "", true, 0},
	{"R2-17", "Path traversal", "double-encoded traversal", "GET", `/static/%252e%252e%252f%252e%252e%252fetc%252fpasswd`, nil, "", true, 0},
	{"R2-18", "SSRF", "metadata address in a path", "GET", `/fetch/http://169.254.169.254/latest/meta-data/`, nil, "", true, 900113},
	{"R2-20", "XSS", "XSS in X-Forwarded-Host", "GET", `/`, map[string]string{"X-Forwarded-Host": `<script>alert(1)</script>`}, "", true, 0},
	{"R2-21", "SQLi", "method override with a SQLi body", "POST", `/api/query?x=1`, map[string]string{"X-HTTP-Method-Override": "PUT", "Content-Type": formCT}, `id=1' OR 1=1--`, true, 0},
	// ---- false-positive guards for the path rules ------------------------
	{"ALLOW-01", "Control", "apostrophe in a path", "GET", `/blog/it's-a-good-day`, nil, "", false, 0},
	{"ALLOW-02", "Control", "ordinary REST path", "GET", `/api/v1/items/42`, nil, "", false, 0},
	{"ALLOW-03", "Control", "select as a word in a path", "GET", `/search/select-options`, nil, "", false, 0},
	{"ALLOW-04", "Control", "and/or as words in a path", "GET", `/docs/and-or-operators`, nil, "", false, 0},
}

// The probes whose wire body is not a plain string: gzip and UTF-16 both reach
// the application intact, so the layer has to decide them too.
type transportCase struct {
	corpusCase
	Encode string // "gzip" or "utf16"
}

var transportCorpus = []transportCase{
	{corpusCase{"R2-01", "Compression", "gzip SQLi body", "POST", `/login`, map[string]string{"Content-Type": formCT, "Content-Encoding": "gzip"}, `user=1' OR 1=1--&pass=x`, true, 0}, "gzip"},
	{corpusCase{"R2-02", "Compression", "gzip XXE body", "POST", `/api/data`, map[string]string{"Content-Type": xmlCT, "Content-Encoding": "gzip"}, `<?xml version="1.0"?><!DOCTYPE d [<!ENTITY e SYSTEM "file:///etc/passwd">]><d>&e;</d>`, true, 0}, "gzip"},
	{corpusCase{"R2-03", "Compression", "gzip XSS body", "POST", `/api/comment`, map[string]string{"Content-Type": jsonCT, "Content-Encoding": "gzip"}, `{"comment":"<script>alert(1)</script>"}`, true, 0}, "gzip"},
	{corpusCase{"R2-05", "Encoding", "UTF-16 XXE body", "POST", `/api/data`, map[string]string{"Content-Type": xmlCT + "; charset=utf-16"}, `<?xml version="1.0"?><!DOCTYPE d [<!ENTITY e SYSTEM "file:///etc/passwd">]><d>&e;</d>`, true, 0}, "utf16"},
	{corpusCase{"R2-06", "Encoding", "UTF-16 form body without a charset", "POST", `/login`, map[string]string{"Content-Type": formCT}, `user=1' OR 1=1--`, true, 0}, "utf16"},
}

func encodeTransport(t *testing.T, body, encoding string) []byte {
	t.Helper()
	switch encoding {
	case "gzip":
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	case "utf16":
		out := []byte{0xff, 0xfe}
		for _, u := range utf16.Encode([]rune(body)) {
			out = append(out, byte(u), byte(u>>8))
		}
		return out
	}
	t.Fatalf("unknown transport encoding %q", encoding)
	return nil
}

// corpusEngine compiles the shipped defaults at paranoia level 1, the setting
// every row is decided against.
func corpusEngine(t *testing.T) *Engine {
	t.Helper()
	id := int64(1)
	set := NewSet([]model.Profile{{
		ID: id, Name: "corpus", Mode: "block", Paranoia: 1, Anomaly: 5, MaxBody: 131072,
	}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	engine := set.For(&id)
	if engine == nil {
		t.Fatal("no engine compiled")
	}
	return engine
}

func corpusRequest(c corpusCase, body []byte) *http.Request {
	req := httptest.NewRequest(c.Method, c.Target, nil)
	if len(body) > 0 {
		// A body without a length trips 920180 before the body rules see
		// anything, which would hide what the probe is testing.
		req.ContentLength = int64(len(body))
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	for k, v := range c.Headers {
		if k == "Host" {
			// httptest carries the authority on the request, not the header map.
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	return req
}

// runCorpus asserts one probe's verdict, and the rule when the row pins one.
func runCorpus(t *testing.T, engine *Engine, c corpusCase, body []byte) {
	t.Run(c.ID, func(t *testing.T) {
		res := engine.Inspect(corpusRequest(c, body), body, netip.MustParseAddr("203.0.113.9"))
		if res.Blocked != c.WantBlocked {
			t.Fatalf("%s (%s): blocked=%v, want %v; rule=%d label=%s",
				c.Technique, c.Category, res.Blocked, c.WantBlocked, res.RuleID, res.Label)
		}
		if c.WantBlocked && c.Rule != 0 && res.RuleID != c.Rule {
			t.Fatalf("%s: blocked by rule %d, want %d", c.Technique, res.RuleID, c.Rule)
		}
	})
}

// TestBypassCorpus runs the review's corpus against the shipped defaults at
// paranoia level 1. It is the regression gate: a new bypass, or a rule that
// stops firing after a CRS bump, fails here.
func TestBypassCorpus(t *testing.T) {
	engine := corpusEngine(t)
	for _, c := range bypassCorpus {
		runCorpus(t, engine, c, []byte(c.Body))
	}
}

// TestTransportCorpus pins the probes a string body cannot carry: the origin
// decodes gzip and UTF-16 the way a framework does, so a body parser that skips
// them hands the attack to the application.
func TestTransportCorpus(t *testing.T) {
	engine := corpusEngine(t)
	for _, c := range transportCorpus {
		runCorpus(t, engine, c.corpusCase, encodeTransport(t, c.corpusCase.Body, c.Encode))
	}
}

// The corpus has to cover the review: every category present, and enough cases
// that a silently deleted row is noticed even when the remaining ones pass.
func TestBypassCorpusIsComplete(t *testing.T) {
	seen := map[string]int{}
	ids := map[string]bool{}
	add := func(c corpusCase) {
		seen[c.Category]++
		if ids[c.ID] {
			t.Fatalf("duplicate probe id %s", c.ID)
		}
		ids[c.ID] = true
	}
	for _, c := range bypassCorpus {
		add(c)
	}
	for _, c := range transportCorpus {
		add(c.corpusCase)
	}
	for _, want := range []string{"SQLi", "XSS", "Path traversal", "RCE", "XXE", "SSRF", "Protocol", "Control", "Compression", "Encoding"} {
		if seen[want] == 0 {
			t.Errorf("no %s probes in the corpus", want)
		}
	}
	// 96 rows: the 70 review probes this layer decides, four XXE variants, the
	// three first round-two bypasses, fifteen more from the follow-up review,
	// and four URL controls that must stay allowed. Five further probes need an
	// encoded body, so they ride in transportCorpus instead.
	if len(bypassCorpus) != 96 {
		t.Errorf("corpus has %d probes, want 96", len(bypassCorpus))
	}
	if len(transportCorpus) != 5 {
		t.Errorf("transport corpus has %d probes, want 5", len(transportCorpus))
	}
}
