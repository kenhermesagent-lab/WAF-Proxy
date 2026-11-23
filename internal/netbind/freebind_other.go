//go:build !linux

package netbind

import (
	"errors"
	"net"
)

// ErrUnsupported is returned where the platform has no IP_FREEBIND.
var ErrUnsupported = errors.New("netbind: IP_FREEBIND is not supported on this platform")

// Listen is unavailable outside Linux.
func Listen(network, address string) (net.Listener, error) { return nil, ErrUnsupported }
