package acme

import (
	"net/http"
	"strings"
	"sync"
)

// HTTP01Challenge serves ACME HTTP-01 tokens from the gateway's own HTTP
// listener instead of letting lego bind port 80 behind the pipeline's back.
type HTTP01Challenge struct {
	mu     sync.RWMutex
	tokens map[string]string
}

// NewHTTP01Challenge creates an empty token store.
func NewHTTP01Challenge() *HTTP01Challenge {
	return &HTTP01Challenge{tokens: map[string]string{}}
}

// Present makes a token available for the duration of one validation.
func (c *HTTP01Challenge) Present(domain, token, keyAuth string) error {
	c.mu.Lock()
	c.tokens[token] = keyAuth
	c.mu.Unlock()
	return nil
}

// CleanUp removes the token after validation.
func (c *HTTP01Challenge) CleanUp(domain, token, keyAuth string) error {
	c.mu.Lock()
	delete(c.tokens, token)
	c.mu.Unlock()
	return nil
}

// ServeHTTP answers /.well-known/acme-challenge/<token>.
func (c *HTTP01Challenge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const prefix = "/.well-known/acme-challenge/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, prefix)
	c.mu.RLock()
	keyAuth, ok := c.tokens[token]
	c.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(keyAuth))
}
