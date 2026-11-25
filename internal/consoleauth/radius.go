package consoleauth

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

const (
	radiusAccessRequest   = 1
	radiusAccessAccept    = 2
	radiusAccessReject    = 3
	radiusAccessChallenge = 11

	radiusAttrUsername     = 1
	radiusAttrReplyMessage = 18
	radiusAttrState        = 24
)

func radiusAttribute(typ byte, value []byte) []byte {
	for len(value) > 253 {
		part := make([]byte, 2+253)
		part[0] = typ
		part[1] = 255
		copy(part[2:], value[:253])
		value = value[253:]
		// A long attribute is unusual for these two types; the caller limits
		// input length, so this branch is only a safety net.
		return append(part, radiusAttribute(typ, value)...)
	}
	out := make([]byte, 2+len(value))
	out[0] = typ
	out[1] = byte(len(out))
	copy(out[2:], value)
	return out
}

// radiusPassword hides the password with the RFC 2865 PAP stream: MD5(secret +
// request authenticator), then each next block uses the previous ciphertext.
func radiusPassword(password, secret, authenticator []byte) []byte {
	if len(password) > 128 {
		password = password[:128]
	}
	padded := make([]byte, (len(password)+15)/16*16)
	if len(padded) == 0 {
		padded = make([]byte, 16)
	}
	copy(padded, password)
	out := make([]byte, len(padded))
	prev := authenticator
	for off := 0; off < len(padded); off += 16 {
		h := md5.New()
		h.Write(secret)
		h.Write(prev)
		sum := h.Sum(nil)
		for i := 0; i < 16; i++ {
			out[off+i] = padded[off+i] ^ sum[i]
		}
		prev = out[off : off+16]
	}
	return out
}

func authenticateRADIUS(ctx context.Context, cfg Config, username, password string) (Result, error) {
	if cfg.Secret == "" {
		return Result{}, errors.New("RADIUS shared secret is not configured")
	}
	if len(username) == 0 || len(username) > 253 {
		return Result{}, ErrInvalidCredentials
	}
	port := cfg.Port
	if port == 0 {
		port = 1812
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(cfg.Host, strconv.Itoa(port)))
	if err != nil {
		return Result{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	authenticator := make([]byte, 16)
	if _, err := rand.Read(authenticator); err != nil {
		return Result{}, err
	}
	identifier := authenticator[0]
	var attrs []byte
	attrs = append(attrs, radiusAttribute(radiusAttrUsername, []byte(username))...)
	attrs = append(attrs, radiusAttribute(2, radiusPassword([]byte(password), []byte(cfg.Secret), authenticator))...)

	length := 20 + len(attrs)
	packet := make([]byte, length)
	packet[0] = radiusAccessRequest
	packet[1] = identifier
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	copy(packet[4:20], authenticator)
	copy(packet[20:], attrs)
	if _, err := conn.Write(packet); err != nil {
		return Result{}, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return Result{}, err
	}
	reply := buf[:n]
	if len(reply) < 20 {
		return Result{}, fmt.Errorf("short RADIUS reply")
	}
	if int(binary.BigEndian.Uint16(reply[2:4])) != n {
		return Result{}, fmt.Errorf("RADIUS reply length mismatch")
	}
	if reply[1] != identifier {
		return Result{}, fmt.Errorf("RADIUS reply identifier mismatch")
	}
	// Verify the Response Authenticator: MD5(Code+ID+Length+RequestAuth+
	// Attributes+Secret). Without this check an off-path packet could approve a
	// sign-in.
	sum := md5.New()
	sum.Write(reply[:4])
	sum.Write(authenticator)
	sum.Write(reply[20:])
	sum.Write([]byte(cfg.Secret))
	if !equalBytes(sum.Sum(nil), reply[4:20]) {
		return Result{}, fmt.Errorf("RADIUS reply authenticator mismatch")
	}

	switch reply[0] {
	case radiusAccessAccept:
		return Result{}, nil
	case radiusAccessReject, radiusAccessChallenge:
		return Result{}, ErrInvalidCredentials
	default:
		return Result{}, fmt.Errorf("unexpected RADIUS code %d", reply[0])
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
