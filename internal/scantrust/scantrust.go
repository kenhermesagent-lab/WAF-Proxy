// Package scantrust holds the per-run tokens that mark a request as this node's
// own security scanner. A token is random and valid only while its run is open,
// so traffic the scanner did not send can never present one: exempting probes
// from bans and decoys opens no hole for anyone else.
package scantrust

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
)

// Header carries a run's token. It goes on every probe and is never written to
// the evidence.
const Header = "X-WAF-Scan"

// Registry is the set of scans in flight.
type Registry struct {
	mu     sync.Mutex
	tokens map[string]struct{}
}

// New returns an empty registry.
func New() *Registry { return &Registry{tokens: map[string]struct{}{}} }

// Begin mints a token for one run. The caller must End it when the run returns,
// so a finished run cannot leave an exemption behind.
func (r *Registry) Begin() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b[:])
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens[token] = struct{}{}
	return token, nil
}

// End retires a token.
func (r *Registry) End(token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.tokens, token)
}

// Valid reports whether a token belongs to a run that is still open.
func (r *Registry) Valid(token string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.tokens[token]
	return ok
}
