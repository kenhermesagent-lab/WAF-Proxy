package proxy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

// respVerdict carries the response phase's decision back to the deferred
// request logger, which has no other way to see it.
type respVerdict struct {
	stage, rule, msg, action string
	blocked                  bool
}

const ctxRespVerdict ctxKey = 2

// errResponseBlocked tells the reverse proxy to refuse the response before its
// status line is written, so the client gets the uniform error page instead.
var errResponseBlocked = errors.New("upstream response blocked by the WAF")

// modifyResponse inspects an upstream response when the profile asks for it.
func (s *Server) modifyResponse(e *edge, res *http.Response) error {
	v, _ := res.Request.Context().Value(ctxRespVerdict).(*respVerdict)
	if v == nil {
		return nil
	}
	responses, mode := s.d.Policy.ResponseInspection(&e.proxy)
	if responses != "flag" && responses != "block" {
		return nil
	}
	eng := s.d.Policy.ResponseEngine(&e.proxy)
	if eng == nil {
		return nil
	}

	reason := skipReason(res)
	var body []byte
	if reason == "" {
		var err error
		if body, reason, err = responseBody(res, eng.MaxBody()); err != nil {
			return err
		}
	}
	if reason != "" {
		v.stage, v.rule = "response-skipped", reason
		v.msg = "upstream response was not inspected"
	}

	verdict, _ := eng.InspectResponse(waf.ResponseInput{
		Status: res.StatusCode, Proto: res.Proto, Header: res.Header, Body: body,
	})
	if !verdict.Matched {
		return nil
	}
	v.stage, v.rule = "response-waf", itoa(verdict.RuleID)
	v.msg = verdict.Label + ": " + verdict.Message
	if verdict.Blocked && responses == "block" && mode == "block" {
		v.action, v.blocked = "block", true
		return errResponseBlocked
	}
	v.action = "log"
	return nil
}

// skipReason names the responses whose body cannot be inspected whole.
func skipReason(res *http.Response) string {
	switch {
	case res.Request.Method == http.MethodHead, res.StatusCode == http.StatusNoContent,
		res.StatusCode == http.StatusNotModified:
		return "no-body"
	case res.StatusCode == http.StatusSwitchingProtocols, res.Header.Get("Upgrade") != "":
		return "upgrade"
	case strings.HasPrefix(strings.ToLower(strings.TrimSpace(res.Header.Get("Content-Type"))), "text/event-stream"):
		return "sse"
	case res.Request.Header.Get("Range") != "":
		return "range"
	case res.Header.Get("Content-Encoding") != "" && !strings.EqualFold(res.Header.Get("Content-Encoding"), "identity"):
		return "encoded"
	}
	return ""
}

// responseBody buffers up to limit bytes and puts them back on the response.
// A body over the limit is handed to the client untouched and reported as
// too-large rather than inspected in part.
func responseBody(res *http.Response, limit int64) ([]byte, string, error) {
	if res.Body == nil {
		return nil, "no-body", nil
	}
	if res.ContentLength > limit {
		return nil, "too-large", nil
	}
	buf, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(buf)) > limit {
		res.Body = readCloser{io.MultiReader(bytes.NewReader(buf), res.Body), res.Body}
		return nil, "too-large", nil
	}
	res.Body = io.NopCloser(bytes.NewReader(buf))
	return buf, "", nil
}

type readCloser struct {
	io.Reader
	io.Closer
}
