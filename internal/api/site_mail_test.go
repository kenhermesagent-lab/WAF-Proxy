package api

import (
	"bufio"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"regexp"
	"strings"
	"testing"
	"time"
)

// smtpSink is a minimal SMTP server that keeps the message bodies a test
// expects the console to send.
type smtpSink struct {
	ln   net.Listener
	msgs chan string
}

func startSMTPSink(t *testing.T) *smtpSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &smtpSink{ln: ln, msgs: make(chan string, 4)}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *smtpSink) port() string {
	_, port, _ := net.SplitHostPort(s.ln.Addr().String())
	return port
}

func (s *smtpSink) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *smtpSink) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	write := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
	write("220 sink ready")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			write("250-sink")
			write("250-AUTH PLAIN")
			write("250-8BITMIME")
			write("250 OK")
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			write("235 2.7.0 authenticated")
		case strings.HasPrefix(cmd, "MAIL FROM:"), strings.HasPrefix(cmd, "RCPT TO:"), cmd == "RSET":
			write("250 OK")
		case cmd == "DATA":
			write("354 go ahead")
			var body strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" || l == ".\n" {
					break
				}
				body.WriteString(l)
			}
			s.msgs <- body.String()
			write("250 queued")
		case cmd == "QUIT":
			write("221 bye")
			return
		default:
			write("250 OK")
		}
	}
}

func (s *smtpSink) next(t *testing.T) string {
	t.Helper()
	select {
	case msg := <-s.msgs:
		return msg
	case <-time.After(5 * time.Second):
		t.Fatal("no mail reached the SMTP sink")
		return ""
	}
}

// decodedMail reads a captured message the way a mail client does, so
// assertions see the text the recipient sees. multipart.Part applies the
// part's Content-Transfer-Encoding itself, so it must not be decoded again.
func decodedMail(t *testing.T, raw string) string {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	read := func(r io.Reader) string {
		body, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		if strings.EqualFold(msg.Header.Get("Content-Transfer-Encoding"), "quoted-printable") {
			return read(quotedprintable.NewReader(msg.Body))
		}
		return read(msg.Body)
	}
	var out strings.Builder
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		out.WriteString(read(p))
	}
	return out.String()
}

// An invitation made on one site's console must be mailed through that site's
// SMTP server and carry a link to that site's console, because the account is
// created there. Reading the default site's channels instead sent the link to a
// console that would reject the token.
func TestInviteUsesTheConsoleSitesMailAndLink(t *testing.T) {
	f := newSiteFixtures(t)
	sink := startSMTPSink(t)
	bravo := f.st.InSite(f.bravo.ID)

	if rec := f.call("console.bravo.test", http.MethodPut, "/api/notifications", f.bravoToken, f.bravoCSRF, "", map[string]string{
		"email_enabled": "1", "smtp_host": "127.0.0.1", "smtp_port": sink.port(),
		"smtp_user": "bravo@example.test", "events": "ban",
	}); rec.Code != http.StatusOK {
		t.Fatalf("bravo notifications = %d: %s", rec.Code, rec.Body.String())
	}

	// The default site has no mail configured at all, so any fallback to its
	// channels fails the invitation outright.
	rec := f.call("console.bravo.test", http.MethodPost, "/api/users/invite", f.bravoToken, f.bravoCSRF, "", map[string]any{
		"email": "new@example.test", "first_name": "New", "last_name": "Admin",
		"role_id": bravo.AdminRoleID(),
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("invite from the bravo console = %d: %s", rec.Code, rec.Body.String())
	}

	raw := sink.next(t)
	sent, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if from := sent.Header.Get("From"); !strings.Contains(from, "bravo@example.test") {
		t.Fatalf("the invitation was sent through another site's SMTP account: %q", from)
	}
	msg := decodedMail(t, raw)
	link := regexp.MustCompile(`http://console\.bravo\.test/#/invite\?token=[A-Za-z0-9_-]+`).FindString(msg)
	if link == "" {
		t.Fatalf("the invitation link does not point at the bravo console:\n%s", msg)
	}
	token := link[strings.Index(link, "token=")+len("token="):]
	if _, ok := bravo.InviteByToken(tokenDigest(token)); !ok {
		t.Fatalf("the invitation was not stored on the bravo site: %q", link)
	}

	// The emailed link resolves on the console it names and not on the other.
	inviteInfo := func(host string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/invite?token="+token, nil)
		req.Host = host
		req.RemoteAddr = "127.0.0.1:5000"
		rec := httptest.NewRecorder()
		f.srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	if code := inviteInfo("console.bravo.test"); code != http.StatusOK {
		t.Fatalf("the invited console answered %d", code)
	}
	if code := inviteInfo("gui.local"); code != http.StatusNotFound {
		t.Fatalf("the default console answered %d for another site's invitation", code)
	}
}
