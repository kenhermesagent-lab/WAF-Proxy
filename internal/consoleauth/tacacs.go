package consoleauth

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	tacacsTypeAuth  = 0x01
	tacacsTypeAuthz = 0x02

	tacacsAuthenStatusPass    = 0x01
	tacacsAuthenStatusFail    = 0x02
	tacacsAuthenStatusGetUser = 0x04
	tacacsAuthenStatusGetPass = 0x05
	tacacsAuthenStatusGetData = 0x06
	tacacsAuthenStatusError   = 0x07

	tacacsAuthorStatusPassAdd = 0x01
	tacacsAuthorStatusPassRep = 0x02
	tacacsAuthorStatusFail    = 0x10
	tacacsAuthorStatusError   = 0x11
)

var errTACACSUnsupported = errors.New("TACACS+ PAP not supported")

type tacacsPacket struct {
	version byte
	typ     byte
	seq     byte
	session uint32
	body    []byte
}

func (p tacacsPacket) header(length int) []byte {
	h := make([]byte, 12)
	h[0] = p.version
	h[1] = p.typ
	h[2] = p.seq
	h[3] = 0 // obfuscated, no single-connect negotiation
	binary.BigEndian.PutUint32(h[4:8], p.session)
	binary.BigEndian.PutUint32(h[8:12], uint32(length))
	return h
}

// tacacsPad XORs a body with the RFC 8907 pseudo pad. Each 16-byte block is
// MD5(session_id || secret || version || seq || previous block), and the first
// block has no previous digest.
func tacacsPad(body []byte, session uint32, secret string, version, seq byte) []byte {
	out := make([]byte, len(body))
	var prev []byte
	sessionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sessionBytes, session)
	for off := 0; off < len(body); off += md5.Size {
		h := md5.New()
		h.Write(sessionBytes)
		h.Write([]byte(secret))
		h.Write([]byte{version, seq})
		h.Write(prev)
		prev = h.Sum(nil)
		for i := 0; i < md5.Size && off+i < len(body); i++ {
			out[off+i] = body[off+i] ^ prev[i]
		}
	}
	return out
}

func tacacsRead(conn net.Conn, secret string) (tacacsPacket, error) {
	head := make([]byte, 12)
	if _, err := io.ReadFull(conn, head); err != nil {
		return tacacsPacket{}, err
	}
	if head[0]>>4 != 0xc {
		return tacacsPacket{}, fmt.Errorf("unsupported TACACS+ version %#x", head[0])
	}
	n := binary.BigEndian.Uint32(head[8:12])
	if n > 1<<16 {
		return tacacsPacket{}, fmt.Errorf("TACACS+ packet too large: %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return tacacsPacket{}, err
	}
	if head[3]&0x01 == 0 {
		body = tacacsPad(body, binary.BigEndian.Uint32(head[4:8]), secret, head[0], head[2])
	}
	return tacacsPacket{
		version: head[0], typ: head[1], seq: head[2],
		session: binary.BigEndian.Uint32(head[4:8]), body: body,
	}, nil
}

func tacacsWrite(conn net.Conn, p tacacsPacket, secret string) error {
	body := tacacsPad(p.body, p.session, secret, p.version, p.seq)
	packet := append(p.header(len(body)), body...)
	_, err := conn.Write(packet)
	return err
}

func randomSession() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func tacacsDial(ctx context.Context, cfg Config) (net.Conn, error) {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	port := cfg.Port
	if port == 0 {
		port = 49
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(cfg.Host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

// tacacsAuthStart builds the login START body. PAP carries the password in
// data; ASCII asks the server for the username and password prompts.
func tacacsAuthStart(username, password string, ascii bool) []byte {
	authenType := byte(2)
	data := password
	if ascii {
		authenType = 1
		data = ""
	}
	body := []byte{1, 1, authenType, 1, byte(len(username)), 0, 0, byte(len(data))}
	body = append(body, []byte(username)...)
	body = append(body, []byte(data)...)
	return body
}

func tacacsAuthRequest(conn net.Conn, secret string, session uint32, seq byte, body []byte) (tacacsPacket, error) {
	if err := tacacsWrite(conn, tacacsPacket{version: 0xc1, typ: tacacsTypeAuth, seq: seq, session: session, body: body}, secret); err != nil {
		return tacacsPacket{}, err
	}
	reply, err := tacacsRead(conn, secret)
	if err != nil {
		return tacacsPacket{}, err
	}
	if reply.typ != tacacsTypeAuth || reply.seq != seq+1 || len(reply.body) == 0 {
		return tacacsPacket{}, fmt.Errorf("unexpected TACACS+ authentication reply")
	}
	return reply, nil
}

// tacacsASCIIDialog answers the server's GETUSER/GETPASS/GETDATA prompts. It
// also runs after a PAP START when the server answers with a prompt instead of
// accepting the password in the packet.
func tacacsASCIIDialog(conn net.Conn, secret string, session uint32, reply tacacsPacket, username, password string) (byte, error) {
	for step := 0; step < 8; step++ {
		var answer string
		switch reply.body[0] {
		case tacacsAuthenStatusPass:
			return tacacsAuthenStatusPass, nil
		case tacacsAuthenStatusFail:
			return tacacsAuthenStatusFail, nil
		case tacacsAuthenStatusGetUser:
			answer = username
		case tacacsAuthenStatusGetPass, tacacsAuthenStatusGetData:
			answer = password
		case tacacsAuthenStatusError:
			return 0, fmt.Errorf("TACACS+ server refused authentication with an error")
		default:
			return 0, fmt.Errorf("unexpected TACACS+ authentication status %d", reply.body[0])
		}
		next, err := tacacsAuthRequest(conn, secret, session, reply.seq+1, []byte(answer))
		if err != nil {
			return 0, err
		}
		reply = next
	}
	return 0, errors.New("TACACS+ server asked for too many authentication prompts")
}

// tacacsPAP reports whether the exchange had to continue as ASCII, so the
// authorization request can name the same authentication type.
func tacacsPAP(ctx context.Context, cfg Config, username, password string) (byte, bool, error) {
	conn, err := tacacsDial(ctx, cfg)
	if err != nil {
		return 0, false, err
	}
	defer conn.Close()
	session, err := randomSession()
	if err != nil {
		return 0, false, err
	}
	// PAP sends the username and password in one START packet, so a console
	// sign-in costs one round trip instead of an ASCII prompt dialogue.
	reply, err := tacacsAuthRequest(conn, cfg.Secret, session, 1, tacacsAuthStart(username, password, false))
	if err != nil {
		return 0, false, fmt.Errorf("%w: %v", errTACACSUnsupported, err)
	}
	switch reply.body[0] {
	case tacacsAuthenStatusPass, tacacsAuthenStatusFail:
		return reply.body[0], false, nil
	case tacacsAuthenStatusGetUser, tacacsAuthenStatusGetPass, tacacsAuthenStatusGetData:
		status, err := tacacsASCIIDialog(conn, cfg.Secret, session, reply, username, password)
		return status, true, err
	default:
		return 0, false, errTACACSUnsupported
	}
}

func tacacsASCII(ctx context.Context, cfg Config, username, password string) (byte, error) {
	conn, err := tacacsDial(ctx, cfg)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	session, err := randomSession()
	if err != nil {
		return 0, err
	}
	reply, err := tacacsAuthRequest(conn, cfg.Secret, session, 1, tacacsAuthStart(username, password, true))
	if err != nil {
		return 0, err
	}
	return tacacsASCIIDialog(conn, cfg.Secret, session, reply, username, password)
}

func authenticateTACACS(ctx context.Context, cfg Config, username, password string) (Result, error) {
	if cfg.Secret == "" {
		return Result{}, errors.New("TACACS+ shared secret is not configured")
	}
	status, ascii, err := tacacsPAP(ctx, cfg, username, password)
	if errors.Is(err, errTACACSUnsupported) {
		// Some servers only implement the ASCII login dialogue. Start a fresh
		// session and let the server prompt for the username and password.
		status, err = tacacsASCII(ctx, cfg, username, password)
		ascii = true
	}
	if err != nil {
		return Result{}, err
	}
	switch status {
	case tacacsAuthenStatusPass:
	case tacacsAuthenStatusFail:
		return Result{}, ErrInvalidCredentials
	default:
		return Result{}, fmt.Errorf("unexpected TACACS+ authentication status %d", status)
	}

	res := Result{}
	// Authorization is a separate session. Its AV pairs carry the role. A
	// refusal or an unreachable authorizer denies the sign-in rather than
	// granting the provider's default role.
	args, authzErr := tacacsAuthorize(ctx, cfg, username, ascii)
	if errors.Is(authzErr, ErrAuthorizationDenied) {
		return Result{}, ErrAuthorizationDenied
	}
	if authzErr != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrDirectoryUnavailable, authzErr)
	}
	for _, av := range args {
		res.Groups = append(res.Groups, av)
		name, value, ok := strings.Cut(av, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(name) {
		case "role", "roles", "console-role":
			if res.RoleHint == "" {
				res.RoleHint = value
			}
		case "priv-lvl", "priv_lvl":
			if res.RoleHint == "" {
				res.RoleHint = value
			}
		}
	}
	return res, nil
}

func tacacsAuthorize(ctx context.Context, cfg Config, username string, ascii bool) ([]string, error) {
	conn, err := tacacsDial(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("TACACS+ authorization: %w", err)
	}
	defer conn.Close()
	session, err := randomSession()
	if err != nil {
		return nil, err
	}
	args := []string{"service=shell", "cmd=*"}
	body := make([]byte, 8, 8+len(args)+len(username)+16)
	body[0] = 6 // TAC_PLUS_AUTHEN_METH_TACACSPLUS
	body[1] = 1
	body[2] = 2 // PAP, matching the authentication exchange
	if ascii {
		body[2] = 1
	}
	body[3] = 1 // login
	body[4] = byte(len(username))
	body[5] = 0
	body[6] = 0
	body[7] = byte(len(args))
	for _, a := range args {
		body = append(body, byte(len(a)))
	}
	body = append(body, []byte(username)...)
	for _, a := range args {
		body = append(body, []byte(a)...)
	}
	if err := tacacsWrite(conn, tacacsPacket{version: 0xc0, typ: tacacsTypeAuthz, seq: 1, session: session, body: body}, cfg.Secret); err != nil {
		return nil, err
	}
	reply, err := tacacsRead(conn, cfg.Secret)
	if err != nil {
		return nil, err
	}
	if reply.typ != tacacsTypeAuthz || reply.seq != 2 || len(reply.body) < 6 {
		return nil, fmt.Errorf("unexpected TACACS+ authorization reply")
	}
	status := reply.body[0]
	count := int(reply.body[1])
	msgLen := int(binary.BigEndian.Uint16(reply.body[2:4]))
	dataLen := int(binary.BigEndian.Uint16(reply.body[4:6]))
	if len(reply.body) < 6+count+msgLen+dataLen {
		return nil, fmt.Errorf("truncated TACACS+ authorization reply")
	}
	switch status {
	case tacacsAuthorStatusPassAdd, tacacsAuthorStatusPassRep:
	case tacacsAuthorStatusFail:
		return nil, ErrAuthorizationDenied
	case tacacsAuthorStatusError:
		return nil, fmt.Errorf("TACACS+ authorization failed with a server error")
	default:
		return nil, fmt.Errorf("unexpected TACACS+ authorization status %d", status)
	}
	pos := 6 + count + msgLen + dataLen
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		n := int(reply.body[6+i])
		if pos+n > len(reply.body) {
			return nil, fmt.Errorf("truncated TACACS+ authorization argument")
		}
		out = append(out, string(reply.body[pos:pos+n]))
		pos += n
	}
	return out, nil
}
