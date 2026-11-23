package waf

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func responseEngine(t *testing.T, exceptions string) *Engine {
	t.Helper()
	e, err := compile(model.Profile{ID: 2, Name: "resp", Mode: "block", Paranoia: 1, Anomaly: 5,
		MaxBody: 131072, Exceptions: exceptions}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// A page that hands the visitor a database error must not reach the browser.
func leakyPage() ResponseInput {
	return ResponseInput{Status: 200, Header: http.Header{"Content-Type": {"text/html"}},
		Body: []byte("<html><body>You have an error in your SQL syntax; check the manual</body></html>")}
}

func TestInspectResponseBlocksLeakyBody(t *testing.T) {
	res, matches := responseEngine(t, "").InspectResponse(leakyPage())
	if !res.Matched || !res.Blocked {
		t.Fatalf("SQL error page was not blocked: %+v (%v)", res, matches)
	}
	if res.RuleID != 951230 {
		t.Fatalf("rule %d is not the MySQL leakage rule", res.RuleID)
	}
	if res.ProfileID != 2 || res.Paranoia != 1 {
		t.Fatalf("verdict lost the profile: %+v", res)
	}
}

func TestInspectResponseAllowsCleanBody(t *testing.T) {
	res, matches := responseEngine(t, "").InspectResponse(ResponseInput{Status: 200,
		Header: http.Header{"Content-Type": {"text/html"}},
		Body:   []byte("<html><body><p>hello</p></body></html>")})
	if res.Matched || res.Blocked || len(matches) != 0 {
		t.Fatalf("clean page matched: %+v (%v)", res, matches)
	}
}

// The operator's exceptions apply to the response phases as well.
func TestInspectResponseHonoursExceptions(t *testing.T) {
	blocked, matches := responseEngine(t, "").InspectResponse(leakyPage())
	if !blocked.Blocked || len(matches) == 0 {
		t.Fatalf("payload did not block without exceptions: %+v (%v)", blocked, matches)
	}
	ids := make([]string, 0, len(matches))
	for _, m := range matches {
		ids = append(ids, strconv.Itoa(m.RuleID))
	}

	res, _ := responseEngine(t, strings.Join(ids, ",")).InspectResponse(leakyPage())
	if res.Matched || res.Blocked {
		t.Fatalf("excepted rules still blocked: %+v", res)
	}
}

// A bodyless response (304, HEAD) still runs the header phase without panicking.
func TestInspectResponseWithoutBody(t *testing.T) {
	res, _ := responseEngine(t, "").InspectResponse(ResponseInput{Status: 304, Proto: "HTTP/1.1"})
	if res.Blocked {
		t.Fatalf("304 was blocked: %+v", res)
	}
}
