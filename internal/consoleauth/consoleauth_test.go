package consoleauth

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestTACACSPadRoundTrip(t *testing.T) {
	body := []byte("a body longer than one MD5 block, with a password in it")
	once := tacacsPad(body, 42, "secret", 0xc0, 1)
	if string(once) == string(body) {
		t.Fatal("the body was not obfuscated")
	}
	twice := tacacsPad(once, 42, "secret", 0xc0, 1)
	if string(twice) != string(body) {
		t.Fatal("the pseudo pad is not reversible")
	}
}

func TestTACACSAuthenticateAndAuthorize(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	done := make(chan error, 1)
	go func() {
		// Authentication: PAP START with the password in data.
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		p, err := tacacsRead(conn, "shared")
		if err != nil {
			done <- err
			return
		}
		if p.typ != tacacsTypeAuth || len(p.body) < 8 {
			done <- errUnexpected("auth packet")
			return
		}
		ulen := int(p.body[4])
		plen := int(p.body[7])
		user := string(p.body[8 : 8+ulen])
		pass := string(p.body[8+ulen : 8+ulen+plen])
		if user != "alice" || pass != "correct horse" {
			done <- errUnexpected("credentials " + user + "/" + pass)
			return
		}
		_ = tacacsWrite(conn, tacacsPacket{version: 0xc1, typ: tacacsTypeAuth, seq: 2, session: p.session,
			body: []byte{tacacsAuthenStatusPass, 0, 0, 0, 0, 0}}, "shared")
		conn.Close()

		// Authorization: the returned priv-lvl becomes the role hint.
		conn, err = ln.Accept()
		if err != nil {
			done <- err
			return
		}
		p, err = tacacsRead(conn, "shared")
		if err != nil {
			done <- err
			return
		}
		if p.typ != tacacsTypeAuthz || p.body[2] != 2 {
			done <- errUnexpected("PAP authorization packet")
			return
		}
		arg := []byte("priv-lvl=15")
		body := []byte{tacacsAuthorStatusPassAdd, 1, 0, 0, 0, 0, byte(len(arg))}
		body = append(body, arg...)
		_ = tacacsWrite(conn, tacacsPacket{version: 0xc0, typ: tacacsTypeAuthz, seq: 2, session: p.session, body: body}, "shared")
		conn.Close()
		done <- nil
	}()

	res, err := Authenticate(context.Background(), Config{
		Kind: "tacacs", Host: "127.0.0.1", Port: port, Secret: "shared", TimeoutSeconds: 3,
	}, "alice", "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if res.RoleHint != "15" {
		t.Fatalf("role hint = %q, want 15", res.RoleHint)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTACACSASCIIPromptFallback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		p, err := tacacsRead(conn, "shared")
		if err != nil {
			done <- err
			return
		}
		if p.typ != tacacsTypeAuth || p.body[2] != 2 {
			done <- errUnexpected("PAP start")
			return
		}
		_ = tacacsWrite(conn, tacacsPacket{version: 0xc1, typ: tacacsTypeAuth, seq: 2, session: p.session,
			body: []byte{tacacsAuthenStatusGetUser, 0, 0, 0, 0, 0}}, "shared")
		p, err = tacacsRead(conn, "shared")
		if err != nil || string(p.body) != "alice" || p.seq != 3 {
			done <- errUnexpected("ASCII username")
			return
		}
		_ = tacacsWrite(conn, tacacsPacket{version: 0xc1, typ: tacacsTypeAuth, seq: 4, session: p.session,
			body: []byte{tacacsAuthenStatusGetPass, 0, 0, 0, 0, 0}}, "shared")
		p, err = tacacsRead(conn, "shared")
		if err != nil || string(p.body) != "correct horse" || p.seq != 5 {
			done <- errUnexpected("ASCII password")
			return
		}
		_ = tacacsWrite(conn, tacacsPacket{version: 0xc1, typ: tacacsTypeAuth, seq: 6, session: p.session,
			body: []byte{tacacsAuthenStatusPass, 0, 0, 0, 0, 0}}, "shared")
		conn.Close()

		conn, err = ln.Accept()
		if err != nil {
			done <- err
			return
		}
		p, err = tacacsRead(conn, "shared")
		if err != nil || p.typ != tacacsTypeAuthz || p.body[2] != 1 {
			done <- errUnexpected("ASCII authorization packet")
			return
		}
		arg := []byte("priv-lvl=15")
		body := []byte{tacacsAuthorStatusPassAdd, 1, 0, 0, 0, 0, byte(len(arg))}
		body = append(body, arg...)
		_ = tacacsWrite(conn, tacacsPacket{version: 0xc0, typ: tacacsTypeAuthz, seq: 2, session: p.session, body: body}, "shared")
		conn.Close()
		done <- nil
	}()

	res, err := Authenticate(context.Background(), Config{
		Kind: "tacacs", Host: "127.0.0.1", Port: port, Secret: "shared", TimeoutSeconds: 3,
	}, "alice", "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if res.RoleHint != "15" {
		t.Fatalf("role hint = %q, want 15", res.RoleHint)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTACACSASCIIAfterUnsupportedPAP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		p, err := tacacsRead(conn, "shared")
		if err != nil || p.body[2] != 2 {
			done <- errUnexpected("PAP start")
			return
		}
		_ = tacacsWrite(conn, tacacsPacket{version: 0xc1, typ: tacacsTypeAuth, seq: 2, session: p.session,
			body: []byte{tacacsAuthenStatusError, 0, 0, 0, 0, 0}}, "shared")
		conn.Close()

		conn, err = ln.Accept()
		if err != nil {
			done <- err
			return
		}
		p, err = tacacsRead(conn, "shared")
		if err != nil || p.typ != tacacsTypeAuth || p.body[2] != 1 {
			done <- errUnexpected("ASCII start")
			return
		}
		_ = tacacsWrite(conn, tacacsPacket{version: 0xc1, typ: tacacsTypeAuth, seq: 2, session: p.session,
			body: []byte{tacacsAuthenStatusGetPass, 0, 0, 0, 0, 0}}, "shared")
		p, err = tacacsRead(conn, "shared")
		if err != nil || string(p.body) != "correct horse" || p.seq != 3 {
			done <- errUnexpected("ASCII password")
			return
		}
		_ = tacacsWrite(conn, tacacsPacket{version: 0xc1, typ: tacacsTypeAuth, seq: 4, session: p.session,
			body: []byte{tacacsAuthenStatusPass, 0, 0, 0, 0, 0}}, "shared")
		conn.Close()

		conn, err = ln.Accept()
		if err != nil {
			done <- err
			return
		}
		p, err = tacacsRead(conn, "shared")
		if err != nil || p.typ != tacacsTypeAuthz || p.body[2] != 1 {
			done <- errUnexpected("ASCII authorization packet")
			return
		}
		_ = tacacsWrite(conn, tacacsPacket{version: 0xc0, typ: tacacsTypeAuthz, seq: 2, session: p.session,
			body: []byte{tacacsAuthorStatusPassAdd, 0, 0, 0, 0, 0}}, "shared")
		conn.Close()
		done <- nil
	}()

	if _, err := Authenticate(context.Background(), Config{
		Kind: "tacacs", Host: "127.0.0.1", Port: port, Secret: "shared", TimeoutSeconds: 3,
	}, "alice", "correct horse"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTACACSAuthorizationDeniedFailsClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		p, err := tacacsRead(conn, "shared")
		if err != nil {
			done <- err
			return
		}
		_ = tacacsWrite(conn, tacacsPacket{version: 0xc1, typ: tacacsTypeAuth, seq: 2, session: p.session,
			body: []byte{tacacsAuthenStatusPass, 0, 0, 0, 0, 0}}, "shared")
		conn.Close()

		conn, err = ln.Accept()
		if err != nil {
			done <- err
			return
		}
		p, err = tacacsRead(conn, "shared")
		if err != nil || p.typ != tacacsTypeAuthz {
			done <- errUnexpected("authorization packet")
			return
		}
		_ = tacacsWrite(conn, tacacsPacket{version: 0xc0, typ: tacacsTypeAuthz, seq: 2, session: p.session,
			body: []byte{tacacsAuthorStatusFail, 0, 0, 0, 0, 0}}, "shared")
		conn.Close()
		done <- nil
	}()

	_, err = Authenticate(context.Background(), Config{
		Kind: "tacacs", Host: "127.0.0.1", Port: port, Secret: "shared", TimeoutSeconds: 3,
	}, "alice", "correct horse")
	if !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("err = %v, want authorization denied", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTACACSAuthorizationUnreachableFailsClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		p, err := tacacsRead(conn, "shared")
		if err != nil {
			done <- err
			return
		}
		_ = tacacsWrite(conn, tacacsPacket{version: 0xc1, typ: tacacsTypeAuth, seq: 2, session: p.session,
			body: []byte{tacacsAuthenStatusPass, 0, 0, 0, 0, 0}}, "shared")
		conn.Close()

		conn, err = ln.Accept()
		if err != nil {
			done <- err
			return
		}
		if _, err := tacacsRead(conn, "shared"); err != nil {
			done <- err
			return
		}
		// Drop the authorization session without a reply.
		conn.Close()
		done <- nil
	}()

	res, err := Authenticate(context.Background(), Config{
		Kind: "tacacs", Host: "127.0.0.1", Port: port, Secret: "shared", TimeoutSeconds: 3,
	}, "alice", "correct horse")
	if !errors.Is(err, ErrDirectoryUnavailable) {
		t.Fatalf("err = %v, want directory unavailable", err)
	}
	if res.RoleHint != "" {
		t.Fatalf("a failed authorization returned role %q", res.RoleHint)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func errUnexpected(what string) error { return &testError{what} }

type testError struct{ what string }

func (e *testError) Error() string { return "unexpected " + e.what }

func TestRADIUSAccessAccept(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			done <- err
			return
		}
		req := append([]byte(nil), buf[:n]...)
		if req[0] != radiusAccessRequest {
			done <- errUnexpected("radius code")
			return
		}
		auth := req[4:20]
		// Decode the PAP attribute.
		var gotUser, gotPass string
		for pos := 20; pos+2 <= len(req); {
			typ := req[pos]
			l := int(req[pos+1])
			if l < 2 || pos+l > len(req) {
				break
			}
			value := req[pos+2 : pos+l]
			if typ == radiusAttrUsername {
				gotUser = string(value)
			}
			if typ == 2 {
				hidden := value
				prev := auth
				var plain []byte
				for off := 0; off+16 <= len(hidden); off += 16 {
					h := md5.New()
					h.Write([]byte("radius-secret"))
					h.Write(prev)
					sum := h.Sum(nil)
					for i := 0; i < 16; i++ {
						plain = append(plain, hidden[off+i]^sum[i])
					}
					prev = hidden[off : off+16]
				}
				gotPass = string(plain)
			}
			pos += l
		}
		if gotUser != "bob" || strings.TrimRight(gotPass, "\x00") != "hunter2" {
			done <- errUnexpected("radius credentials " + gotUser + "/" + gotPass)
			return
		}
		reply := make([]byte, 20)
		reply[0] = radiusAccessAccept
		reply[1] = req[1]
		binary.BigEndian.PutUint16(reply[2:4], 20)
		copy(reply[4:20], auth)
		sum := md5.New()
		sum.Write(reply[:4])
		sum.Write(auth)
		sum.Write([]byte("radius-secret"))
		copy(reply[4:20], sum.Sum(nil))
		_, err = pc.WriteTo(reply, addr)
		done <- err
	}()

	_, err = Authenticate(context.Background(), Config{
		Kind: "radius", Host: "127.0.0.1", Port: port, Secret: "radius-secret", TimeoutSeconds: 3,
	}, "bob", "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTACACSRejectsOversizedFields(t *testing.T) {
	if _, err := Authenticate(context.Background(), Config{Kind: "tacacs"}, string(make([]byte, 300)), "x"); err != ErrInvalidCredentials {
		t.Fatalf("err = %v, want invalid credentials", err)
	}
}

func TestRADIUSPasswordChangesWithAuthenticator(t *testing.T) {
	a := radiusPassword([]byte("password"), []byte("secret"), make([]byte, 16))
	b := radiusPassword([]byte("password"), []byte("secret"), []byte("0123456789abcdef"))
	if string(a) == string(b) {
		t.Fatal("the encrypted password does not depend on the request authenticator")
	}
}
