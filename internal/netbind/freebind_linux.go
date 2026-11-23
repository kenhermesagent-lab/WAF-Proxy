//go:build linux

// Package netbind opens listeners that need options the standard library does
// not expose.
package netbind

import (
	"context"
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// ErrUnsupported is returned where the platform has no IP_FREEBIND.
var ErrUnsupported = errors.New("netbind: IP_FREEBIND is not supported on this platform")

// Listen binds address with IP_FREEBIND set, so a node can hold the service
// address before the kernel moves it there. It is only for VIP mode; a normal
// listener must fail on an address the host does not own.
func Listen(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_FREEBIND, 1)
		}); err != nil {
			return err
		}
		return sockErr
	}}
	return lc.Listen(context.Background(), network, address)
}
