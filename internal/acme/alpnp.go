package acme

import (
	"crypto/tls"
	"strings"
	"sync"

	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
)

// ALPNChallenge serves TLS-ALPN-01 validations from the existing WAN listener
// instead of lego's built-in server, which would need to bind port 443 a second
// time. The proxy asks it for a certificate whenever the handshake offers the
// acme-tls/1 protocol.
type ALPNChallenge struct {
	mu     sync.RWMutex
	active map[string]*tls.Certificate
}

// NewALPNChallenge returns an empty challenge store.
func NewALPNChallenge() *ALPNChallenge {
	return &ALPNChallenge{active: map[string]*tls.Certificate{}}
}

// Present builds the validation certificate lego expects for domain.
func (a *ALPNChallenge) Present(domain, token, keyAuth string) error {
	cert, err := tlsalpn01.ChallengeCert(domain, keyAuth)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.active[strings.ToLower(strings.TrimSuffix(domain, "."))] = cert
	a.mu.Unlock()
	return nil
}

// CleanUp removes the validation certificate after the order finishes.
func (a *ALPNChallenge) CleanUp(domain, token, keyAuth string) error {
	a.mu.Lock()
	delete(a.active, strings.ToLower(strings.TrimSuffix(domain, ".")))
	a.mu.Unlock()
	return nil
}

// Certificate returns the pending validation certificate for a handshake that
// negotiated acme-tls/1.
func (a *ALPNChallenge) Certificate(serverName string, protos []string) (*tls.Certificate, bool) {
	if !hasProto(protos, tlsalpn01.ACMETLS1Protocol) {
		return nil, false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	cert, ok := a.active[strings.ToLower(strings.TrimSuffix(serverName, "."))]
	return cert, ok
}

// Pending reports whether a validation certificate is waiting for a domain.
func (a *ALPNChallenge) Pending(serverName string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, ok := a.active[strings.ToLower(strings.TrimSuffix(serverName, "."))]
	return ok
}

func hasProto(protos []string, want string) bool {
	for _, p := range protos {
		if p == want {
			return true
		}
	}
	return false
}
