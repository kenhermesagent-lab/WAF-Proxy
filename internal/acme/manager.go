// Package acme issues and renews Let's Encrypt certificates with DNS-01.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	mrand "math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// Manager owns the ACME account and the certificate cache.
type Manager struct {
	st  *store.Store
	box *wfcrypto.Box
	log *slog.Logger

	mu sync.RWMutex
	// order serialises ACME orders (DuckDNS stores one TXT record per domain).
	order  sync.Mutex
	certs  []cached
	alpn   *ALPNChallenge
	http01 *HTTP01Challenge
	now    func() time.Time

	// directory overrides the public Let's Encrypt directory (private ACME
	// server for tests or an on-prem CA); caFile is its PEM trust root.
	directory string
	caFile    string

	// Failed renewals back off instead of hammering the CA every cycle.
	retryMu sync.Mutex
	retryAt map[int64]time.Time
	retryN  map[int64]int
}

type cached struct {
	id      int64
	domains []string
	cert    *tls.Certificate
	expires time.Time
}

type account struct {
	email string
	key   crypto.PrivateKey
	reg   *registration.Resource
}

func (a *account) GetEmail() string                         { return a.email }
func (a *account) GetPrivateKey() crypto.PrivateKey         { return a.key }
func (a *account) GetRegistration() *registration.Resource  { return a.reg }
func (a *account) SetRegistration(r *registration.Resource) { a.reg = r }

// New creates a manager and loads existing certificates.
func New(st *store.Store, box *wfcrypto.Box, log *slog.Logger) *Manager {
	m := &Manager{st: st, box: box, log: log, alpn: NewALPNChallenge(), http01: NewHTTP01Challenge(),
		now: time.Now, retryAt: map[int64]time.Time{}, retryN: map[int64]int{}}
	if err := m.Load(); err != nil {
		log.Error("load certificates", "err", err)
	}
	return m
}

// TLSALPN returns the challenge store the proxy's TLS listener consults for
// acme-tls/1 handshakes.
func (m *Manager) TLSALPN() *ALPNChallenge { return m.alpn }

// HTTP01 returns the token handler the gateway's plain-HTTP listener serves.
func (m *Manager) HTTP01() *HTTP01Challenge { return m.http01 }

// Load refreshes the in-memory certificate cache from the database.
func (m *Manager) Load() error {
	certs, err := m.st.ListCerts()
	if err != nil {
		return err
	}
	out := make([]cached, 0, len(certs))
	for _, c := range certs {
		if c.Status != "issued" && c.Status != "renewing" {
			continue
		}
		full, err := m.st.GetCert(c.ID)
		if err != nil || len(full.CertPEM) == 0 {
			continue
		}
		pair, err := tls.X509KeyPair(full.CertPEM, full.KeyPEM)
		if err != nil {
			m.log.Warn("skip unparsable certificate", "domains", c.Domains, "err", err)
			continue
		}
		exp := time.Time{}
		if full.ExpiresAt != nil {
			exp = *full.ExpiresAt
		}
		out = append(out, cached{
			id:      c.ID,
			domains: splitDomains(c.Domains),
			cert:    &pair,
			expires: exp,
		})
	}
	m.mu.Lock()
	m.certs = out
	m.mu.Unlock()
	m.log.Info("certificates loaded", "count", len(out))
	return nil
}

func splitDomains(s string) []string {
	out := []string{}
	for _, d := range strings.Split(s, ",") {
		if d = strings.TrimSpace(strings.ToLower(d)); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// GetCertificate resolves a certificate for TLS SNI.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.CertificateForHost(hello.ServerName)
}

// CertificateForHost resolves a certificate for a fixed name, which is how the
// admin console selects its certificate before any SNI is seen.
func (m *Manager) CertificateForHost(name string) (*tls.Certificate, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if host == "" {
		return nil, errors.New("empty server name")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if cert := selectForHost(host, m.certs, m.now()); cert != nil {
		return cert, nil
	}
	return nil, fmt.Errorf("no certificate for %s", host)
}

// Revoke asks the CA to revoke the certificate. Uploaded and internal
// certificates have no ACME account, so only the local record goes away.
func (m *Manager) Revoke(id int64) error {
	row, err := m.st.GetCert(id)
	if err != nil {
		return err
	}
	if row.Source != model.CertSourceACME || len(row.CertPEM) == 0 {
		return nil
	}
	m.order.Lock()
	defer m.order.Unlock()
	acct, err := m.account()
	if err != nil {
		return err
	}
	cfg, err := m.legoConfig(acct)
	if err != nil {
		return err
	}
	client, err := lego.NewClient(cfg)
	if err != nil {
		return err
	}
	if acct.reg == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return err
		}
		acct.reg = reg
	}
	return client.Certificate.Revoke(row.CertPEM)
}

// SetDirectory points issuance and revocation at a private ACME server.
func (m *Manager) SetDirectory(directory, caFile string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.directory, m.caFile = strings.TrimSpace(directory), strings.TrimSpace(caFile)
}

// legoConfig builds the client configuration, preferring a configured private
// directory over the staging toggle and the public production endpoint.
func (m *Manager) legoConfig(acct *account) (*lego.Config, error) {
	m.mu.RLock()
	directory, caFile := m.directory, m.caFile
	m.mu.RUnlock()
	cfg := lego.NewConfig(acct)
	switch {
	case directory != "":
		cfg.CADirURL = directory
	case stagingSetting(m.st):
		cfg.CADirURL = lego.LEDirectoryStaging
	default:
		cfg.CADirURL = lego.LEDirectoryProduction
	}
	if caFile == "" {
		return cfg, nil
	}
	raw, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read ACME CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("ACME CA file %s holds no certificates", caFile)
	}
	cfg.HTTPClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: pool,
		}},
	}
	return cfg, nil
}

func stagingSetting(st *store.Store) bool {
	v, _ := st.GetSetting("acme_staging")
	return v == "1"
}

// CertificateByID returns the certificate a site named explicitly.
func (m *Manager) CertificateByID(id int64) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := m.now()
	for _, c := range m.certs {
		if c.id == id && now.Before(c.expires) {
			return c.cert, nil
		}
	}
	return nil, fmt.Errorf("certificate %d is not loaded", id)
}

// selectForHost prefers an exact name, then the longest matching wildcard
// pattern. Ranking by the matched pattern (not by domains[0]) is what makes
// multi-name certificates resolve correctly.
func selectForHost(host string, certs []cached, now time.Time) *tls.Certificate {
	best := -1
	bestLen := -1
	for i, c := range certs {
		if !now.Before(c.expires) {
			continue
		}
		for _, d := range c.domains {
			if d == host {
				return c.cert
			}
			if strings.HasPrefix(d, "*.") && wildcardMatch(d, host) && len(d) > bestLen {
				best, bestLen = i, len(d)
			}
		}
	}
	if best >= 0 {
		return certs[best].cert
	}
	return nil
}

func wildcardMatch(pattern, host string) bool {
	suffix := pattern[1:] // ".example.com"
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	rest := strings.TrimSuffix(host, suffix)
	return rest != "" && !strings.Contains(rest, ".")
}

// Issue requests a certificate for a stored row and persists the result.
func (m *Manager) Issue(id int64) error {
	// The order mutex (not the cache mutex) is held for the whole ACME flow, so
	// Load can take the cache lock afterwards without a self-deadlock.
	m.order.Lock()
	defer m.order.Unlock()

	row, err := m.st.GetCert(id)
	if err != nil {
		return err
	}
	domains := splitDomains(row.Domains)
	if len(domains) == 0 {
		return errors.New("certificate has no domains")
	}

	challengeType := row.Challenge
	if !model.ValidCertChallenge(challengeType) {
		challengeType = model.CertChallengeDNS
	}
	var provider challenge.Provider
	if challengeType == model.CertChallengeDNS {
		provider, err = m.provider(row.Provider)
		if err != nil {
			m.fail(id, err)
			return err
		}
	}
	acct, err := m.account()
	if err != nil {
		m.fail(id, err)
		return err
	}

	cfg, err := m.legoConfig(acct)
	if err != nil {
		return err
	}
	client, err := lego.NewClient(cfg)
	if err != nil {
		m.fail(id, err)
		return err
	}
	switch challengeType {
	case model.CertChallengeHTTP:
		if err := client.Challenge.SetHTTP01Provider(m.http01); err != nil {
			m.fail(id, err)
			return err
		}
	case model.CertChallengeTLSALPN:
		if err := client.Challenge.SetTLSALPN01Provider(m.alpn); err != nil {
			m.fail(id, err)
			return err
		}
	default:
		if err := client.Challenge.SetDNS01Provider(provider); err != nil {
			m.fail(id, err)
			return err
		}
	}
	if acct.reg == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			m.fail(id, err)
			return err
		}
		acct.reg = reg
		if err := m.persistRegistration(reg); err != nil {
			m.log.Warn("persist ACME registration", "err", err)
		}
	}

	m.log.Info("requesting certificate", "domains", domains, "provider", row.Provider, "challenge", challengeType)
	res, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	})
	if err != nil {
		m.fail(id, err)
		return err
	}

	leaf, err := parseLeaf(res.Certificate)
	if err != nil {
		m.fail(id, err)
		return err
	}
	now := m.now()
	row.CertPEM = res.Certificate
	row.KeyPEM = res.PrivateKey
	row.Status = "issued"
	row.IssuedAt = &now
	row.ExpiresAt = &leaf.NotAfter
	row.LastError = ""
	row.Wildcard = containsWildcard(domains)
	if _, err := m.st.SaveCert(row); err != nil {
		return err
	}
	if err := m.Load(); err != nil {
		return err
	}
	m.log.Info("certificate issued", "domains", domains, "expires", leaf.NotAfter)
	return nil
}

func (m *Manager) fail(id int64, err error) {
	row, gerr := m.st.GetCert(id)
	if gerr != nil {
		return
	}
	row.LastError = err.Error()
	if len(row.LastError) > 300 {
		row.LastError = row.LastError[:300]
	}
	// A failed renewal must keep serving the previous certificate. Only an
	// initial issuance has no certificate to fall back to.
	if len(row.CertPEM) > 0 {
		row.Status = "issued"
	} else {
		row.Status = "error"
	}
	_, _ = m.st.SaveCert(row)
	m.log.Error("certificate request failed", "domains", row.Domains, "err", err)
}

func parseLeaf(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no certificate PEM found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func containsWildcard(domains []string) bool {
	for _, d := range domains {
		if strings.HasPrefix(d, "*.") {
			return true
		}
	}
	return false
}

const renewSafetyWindow = 7 * 24 * time.Hour

// RenewLoop applies each certificate's renewal policy. The safety window keeps
// a quarterly policy from waiting until a 90-day Let's Encrypt certificate has
// already expired.
func (m *Manager) RenewLoop(ctx context.Context) {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.renewDue()
		}
	}
}

func (m *Manager) renewDue() {
	certs, err := m.st.ListCerts()
	if err != nil {
		return
	}
	for _, c := range certs {
		if c.Status != "issued" || c.ExpiresAt == nil {
			continue
		}
		if !renewalDue(c, m.now()) || !m.renewalAllowed(c.ID, m.now()) {
			continue
		}
		if err := m.Issue(c.ID); err != nil {
			m.scheduleRetry(c.ID, m.now())
			m.log.Warn("renewal failed", "domains", c.Domains, "err", err)
			continue
		}
		m.clearRetry(c.ID)
	}
}

// renewalBackoff is the wait after the nth consecutive failure: 30 minutes,
// doubling up to six hours.
func renewalBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := 30 * time.Minute
	for i := 1; i < attempt && d < 6*time.Hour; i++ {
		d *= 2
	}
	if d > 6*time.Hour {
		d = 6 * time.Hour
	}
	return d
}

func (m *Manager) renewalAllowed(id int64, now time.Time) bool {
	m.retryMu.Lock()
	defer m.retryMu.Unlock()
	at, ok := m.retryAt[id]
	return !ok || !now.Before(at)
}

func (m *Manager) scheduleRetry(id int64, now time.Time) {
	m.retryMu.Lock()
	defer m.retryMu.Unlock()
	m.retryN[id]++
	d := renewalBackoff(m.retryN[id])
	// Up to 20% jitter, so many certificates failing together do not retry in
	// lockstep against the same CA.
	if jitter := time.Duration(mrand.Int63n(int64(d) / 5)); jitter > 0 {
		d += jitter
	}
	m.retryAt[id] = now.Add(d)
}

func (m *Manager) clearRetry(id int64) {
	m.retryMu.Lock()
	delete(m.retryAt, id)
	delete(m.retryN, id)
	m.retryMu.Unlock()
}

func renewalDue(c model.Cert, now time.Time) bool {
	at, ok := renewalTime(c)
	return ok && !now.Before(at)
}

// renewalTime returns when the selected policy next wants a renewal. Policies
// measured from issuance are capped at seven days before expiry.
func renewalTime(c model.Cert) (time.Time, bool) {
	if c.ExpiresAt == nil {
		return time.Time{}, false
	}
	expires := *c.ExpiresAt
	latest := expires.Add(-renewSafetyWindow)
	months := 0
	switch c.RenewMode {
	case model.CertRenewMonthly:
		months = 1
	case model.CertRenewEvery2Months:
		months = 2
	case model.CertRenewEvery3Months:
		months = 3
	}
	at := expires.AddDate(0, -1, 0)
	if months > 0 && c.IssuedAt != nil {
		at = c.IssuedAt.AddDate(0, months, 0)
	}
	if at.After(latest) {
		at = latest
	}
	return at, true
}

func (m *Manager) account() (*account, error) {
	keyPEM, err := m.st.GetSetting("acme_account_key")
	email, _ := m.st.GetSetting("acme_email")
	acct := &account{email: email}
	var key crypto.PrivateKey
	if err == nil && keyPEM != "" {
		plain, derr := m.box.Open(keyPEM)
		if derr == nil {
			key = parseKey([]byte(plain))
		}
	}
	if key == nil {
		k, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if gerr != nil {
			return nil, gerr
		}
		der, gerr := x509.MarshalECPrivateKey(k)
		if gerr != nil {
			return nil, gerr
		}
		enc, serr := m.box.Seal(string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})))
		if serr != nil {
			return nil, serr
		}
		if err := m.st.SetSetting("acme_account_key", enc); err != nil {
			return nil, err
		}
		key = k
	}
	acct.key = key

	if raw, err := m.st.GetSetting("acme_registration"); err == nil && raw != "" {
		if plain, derr := m.box.Open(raw); derr == nil {
			var reg registration.Resource
			if json.Unmarshal([]byte(plain), &reg) == nil {
				acct.reg = &reg
			}
		}
	}
	return acct, nil
}

func (m *Manager) persistRegistration(reg *registration.Resource) error {
	raw, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	enc, err := m.box.Seal(string(raw))
	if err != nil {
		return err
	}
	return m.st.SetSetting("acme_registration", enc)
}

func parseKey(pemBytes []byte) crypto.PrivateKey {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return k
	}
	return nil
}

// provider builds a DNS-01 challenge provider from stored credentials.
func (m *Manager) provider(name string) (challenge.Provider, error) {
	enc, err := m.st.DNSCredentialFor(name)
	if err != nil {
		return nil, fmt.Errorf("no DNS credentials configured for %s", name)
	}
	raw, err := m.box.Open(enc)
	if err != nil {
		return nil, err
	}
	creds := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &creds); err != nil {
		return nil, fmt.Errorf("invalid credentials for %s: %w", name, err)
	}
	return buildProvider(name, creds)
}

// CertSummary is the API representation of a certificate.
func (m *Manager) CertSummary(c model.Cert) map[string]any {
	expires := ""
	if c.ExpiresAt != nil {
		expires = c.ExpiresAt.Format(time.RFC3339)
	}
	mode := c.RenewMode
	if !model.ValidCertRenewMode(mode) {
		mode = model.CertRenewBeforeExpiry
	}
	challenge := c.Challenge
	if !model.ValidCertChallenge(challenge) {
		challenge = model.CertChallengeDNS
	}
	out := map[string]any{
		"id": c.ID, "domains": c.Domains, "provider": c.Provider, "status": c.Status,
		"expires_at": expires, "wildcard": c.Wildcard, "renew_mode": mode, "challenge": challenge,
		"last_error": c.LastError,
	}
	if at, ok := renewalTime(c); ok {
		out["renews_at"] = at.Format(time.RFC3339)
	}
	return out
}
