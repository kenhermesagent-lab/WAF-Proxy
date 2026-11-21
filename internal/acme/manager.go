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
	order sync.Mutex
	certs []cached
	now   func() time.Time
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
	m := &Manager{st: st, box: box, log: log, now: time.Now}
	if err := m.Load(); err != nil {
		log.Error("load certificates", "err", err)
	}
	return m
}

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
	host := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	if host == "" {
		return nil, errors.New("empty server name")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	best := -1
	for i, c := range m.certs {
		if !m.now().Before(c.expires) {
			continue
		}
		for _, d := range c.domains {
			if d == host {
				return c.cert, nil
			}
			if strings.HasPrefix(d, "*.") && wildcardMatch(d, host) {
				if best == -1 || len(d) > len(m.certs[best].domains[0]) {
					best = i
				}
			}
		}
	}
	if best >= 0 {
		return m.certs[best].cert, nil
	}
	return nil, fmt.Errorf("no certificate for %s", host)
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

	provider, err := m.provider(row.Provider)
	if err != nil {
		m.fail(id, err)
		return err
	}
	acct, err := m.account()
	if err != nil {
		m.fail(id, err)
		return err
	}

	cfg := lego.NewConfig(acct)
	if staging, _ := m.st.GetSetting("acme_staging"); staging == "1" {
		cfg.CADirURL = lego.LEDirectoryStaging
	} else {
		cfg.CADirURL = lego.LEDirectoryProduction
	}
	client, err := lego.NewClient(cfg)
	if err != nil {
		m.fail(id, err)
		return err
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		m.fail(id, err)
		return err
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

	m.log.Info("requesting certificate", "domains", domains, "provider", row.Provider)
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
		if renewalDue(c, m.now()) {
			if err := m.Issue(c.ID); err != nil {
				m.log.Warn("renewal failed", "domains", c.Domains, "err", err)
			}
		}
	}
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
	out := map[string]any{
		"id": c.ID, "domains": c.Domains, "provider": c.Provider, "status": c.Status,
		"expires_at": expires, "wildcard": c.Wildcard, "renew_mode": mode, "last_error": c.LastError,
	}
	if at, ok := renewalTime(c); ok {
		out["renews_at"] = at.Format(time.RFC3339)
	}
	return out
}
