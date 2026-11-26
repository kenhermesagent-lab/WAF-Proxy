package scan

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/scantrust"
)

// The raw wire shapes. net/http normalises every one of them away, so they are
// written out byte for byte and sent on a connection of their own. They are
// never replayed at the upstream: two of them desynchronise a connection on
// purpose, and a desynchronised connection carrying somebody else's request is
// not a read-only test.

// framingCLTE sends a body whose Content-Length and chunked framing disagree, so
// an edge that trusts the length leaves the trailing byte in the connection.
func framingCLTE(probePath, host string) string {
	return "POST " + probePath + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 6\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Connection: close\r\n" +
		"\r\n" +
		"0\r\n\r\nG"
}

// framingTECL is the same disagreement in the other direction: chunked framing
// the edge honours, a length the next layer may instead.
func framingTECL(probePath, host string) string {
	body := "0\r\n\r\n"
	return "POST " + probePath + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Content-Length: 3\r\n" +
		"Connection: close\r\n" +
		"\r\n" + body
}

// absoluteForm asks for a full URL in the request target, which a proxy may
// obey as a forwarding instruction.
func absoluteForm(probePath, host string) string {
	return "GET http://" + host + probePath + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Connection: close\r\n\r\n"
}

// http10 is the pre-Host-header protocol version.
func http10(probePath, host string) string {
	return "GET " + probePath + " HTTP/1.0\r\n" +
		"Host: " + host + "\r\n\r\n"
}

// withHeader inserts one header line after the request line, leaving the rest
// of the hand-written request byte for byte as it was.
func withHeader(raw, name, value string) string {
	if i := strings.Index(raw, "\r\n"); i >= 0 {
		return raw[:i+2] + name + ": " + value + "\r\n" + raw[i+2:]
	}
	return raw
}

// sendRaw writes a ready-made request to the published endpoint and reads the
// answer. The connection is closed afterwards, so nothing that follows on the
// wire can reach another request.
func (r *Runner) sendRaw(ctx context.Context, raw string) (answer, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	ep := r.wan
	addr := ep.URL.Host
	if ep.URL.Port() == "" {
		port := "80"
		if ep.URL.Scheme == "https" {
			port = "443"
		}
		addr = net.JoinHostPort(ep.URL.Hostname(), port)
	}
	dialer := &net.Dialer{Timeout: probeTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return answer{}, err
	}
	defer conn.Close()
	if ep.URL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: ep.Host})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return answer{}, err
		}
		conn = tlsConn
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	r.noteSource(conn.LocalAddr())
	if r.Token != "" {
		raw = withHeader(raw, scantrust.Header, r.Token)
	}
	if _, err := io.WriteString(conn, raw); err != nil {
		return answer{}, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return answer{}, fmt.Errorf("read raw answer: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes))
	if err != nil {
		return answer{}, err
	}
	return answer{status: resp.StatusCode, header: resp.Header.Clone(), body: body}, nil
}
