// Package bundle delivers signed attack-signature packs to the WAF.
//
// The channel is deliberately small: one signed manifest that carries a few
// hundred bytes per bundle, and one pack file downloaded only when a version
// changes. A pack contains rules only — never addresses — so a bundle can add
// attack signatures but can never ban an IP; that stays in package intel.
package bundle

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

const (
	maxManifestBytes = 1 << 20 // a manifest is a few KB; anything larger is wrong
	maxPackBytes     = 4 << 20
	maxBundles       = 64
	maxRulesPerPack  = 5000
	keepVersions     = 2
)

// Manifest is the signed inventory of the channel.
type Manifest struct {
	Sequence  int64     `json:"sequence"`
	Generated time.Time `json:"generated,omitempty"`
	Bundles   []Ref     `json:"bundles"`
}

// Ref is one bundle version a manifest advertises.
type Ref struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Rules   int    `json:"rules"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	Path    string `json:"path"`
}

// Pack is the downloaded rule set. Its fields must agree with the manifest
// entry that pointed at it, which is what makes the checksum meaningful.
type Pack struct {
	Bundle  string           `json:"bundle"`
	Version string           `json:"version"`
	Rules   []waf.BundleRule `json:"rules"`
}

// Provider is one signed channel: the manifest URL and the publisher key it
// must be signed with. Providers are checked and downloaded independently.
// Bundle names must be unique across providers, because a profile switches
// them by name.
type Provider struct {
	Name      string
	URL       string
	PublicKey string
}

// Config describes the channel. A provider without both a URL and a public
// key leaves it disabled: the manager then serves whatever is already on disk.
type Config struct {
	Dir       string
	Providers []Provider
	Interval  time.Duration
	Log       *slog.Logger
}

// ParseProviders builds the provider list from the console setting and from
// the single channel the older environment variables configured. The JSON form
// is [{"name":"vendor","url":"https://…/manifest.json","public_key":"…"}];
// the legacy pair keeps working as the provider named "default".
func ParseProviders(raw, legacyURL, legacyKey string) ([]Provider, error) {
	var out []Provider
	if raw = strings.TrimSpace(raw); raw != "" {
		var entries []struct {
			Name      string `json:"name"`
			URL       string `json:"url"`
			PublicKey string `json:"public_key"`
		}
		if err := json.Unmarshal([]byte(raw), &entries); err != nil {
			return nil, fmt.Errorf("WAFPROXY_BUNDLE_PROVIDERS is not a JSON list: %w", err)
		}
		for _, e := range entries {
			name, u, key := strings.TrimSpace(e.Name), strings.TrimSpace(e.URL), strings.TrimSpace(e.PublicKey)
			if name == "" || u == "" || key == "" {
				return nil, errors.New("WAFPROXY_BUNDLE_PROVIDERS: every provider needs a name, url and public_key")
			}
			out = append(out, Provider{Name: name, URL: u, PublicKey: key})
		}
	}
	legacyURL, legacyKey = strings.TrimSpace(legacyURL), strings.TrimSpace(legacyKey)
	if legacyURL != "" || legacyKey != "" {
		out = append(out, Provider{Name: "default", URL: legacyURL, PublicKey: legacyKey})
	}
	return out, nil
}

// Status is the channel as the console shows it: one entry per provider and
// every installed pack across them.
type Status struct {
	Providers []ProviderStatus `json:"providers"`
	Bundles   []BundleStatus   `json:"bundles"`
}

// ProviderStatus is one publisher's channel state.
type ProviderStatus struct {
	Name       string     `json:"name"`
	Configured bool       `json:"configured"`
	URL        string     `json:"url,omitempty"`
	KeyID      string     `json:"key_id,omitempty"`
	LastCheck  *time.Time `json:"last_check,omitempty"`
	NextCheck  *time.Time `json:"next_check,omitempty"`
	Sequence   int64      `json:"sequence"`
	Error      string     `json:"error,omitempty"`
}

// BundleStatus is one installed pack.
type BundleStatus struct {
	Provider    string     `json:"provider,omitempty"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Rules       int        `json:"rules"`
	Size        int64      `json:"size"`
	SHA256      string     `json:"sha256"`
	InstalledAt *time.Time `json:"installed_at,omitempty"`
}

// RuleInfo names the pack a rule ID belongs to, so the console can group hits
// without storing the bundle name on every event.
type RuleInfo struct {
	Provider string
	Bundle   string
	Version  string
	Message  string
}

type bundleState struct {
	Provider    string    `json:"provider,omitempty"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Rules       int       `json:"rules"`
	Size        int64     `json:"size"`
	SHA256      string    `json:"sha256"`
	InstalledAt time.Time `json:"installed_at"`
}

// providerState is per publisher: its own sequence, ETag and last result. The
// sequence is what stops one mirror from rolling a channel back.
type providerState struct {
	Sequence  int64      `json:"sequence"`
	ETag      string     `json:"etag,omitempty"`
	LastCheck *time.Time `json:"last_check,omitempty"`
	LastError string     `json:"last_error,omitempty"`
}

type state struct {
	Providers map[string]*providerState `json:"providers"`
	Bundles   []bundleState             `json:"bundles"`
	// Legacy single-channel fields. They are read once on Load and then
	// cleared, so an install from before providers keeps its sequence.
	Sequence  int64      `json:"sequence,omitempty"`
	ETag      string     `json:"etag,omitempty"`
	LastCheck *time.Time `json:"last_check,omitempty"`
	LastError string     `json:"last_error,omitempty"`
}

// provider is one configured channel with its own publisher and state.
type provider struct {
	name     string
	url      string
	pub      ed25519.PublicKey
	keyID    string
	st       providerState
	checking atomic.Bool
}

// configured reports whether both halves of the channel are present.
func (p *provider) configured() bool {
	return p.url != "" && len(p.pub) == ed25519.PublicKeySize
}

// Manager owns the installed packs, the providers and the refresh loop.
type Manager struct {
	dir       string
	interval  time.Duration
	log       *slog.Logger
	client    *http.Client
	now       func() time.Time
	providers []*provider

	mu       sync.RWMutex
	st       state
	packs    []waf.Bundle
	index    map[int]RuleInfo
	onChange func()
}

// New validates the configuration and prepares the on-disk layout.
func New(cfg Config) (*Manager, error) {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	m := &Manager{
		dir:      cfg.Dir,
		interval: cfg.Interval,
		log:      log,
		client:   &http.Client{Timeout: 45 * time.Second},
		now:      time.Now,
		index:    map[int]RuleInfo{},
	}
	if m.interval <= 0 {
		m.interval = time.Hour
	}
	if m.interval < 5*time.Minute {
		m.interval = 5 * time.Minute
	}
	seen := map[string]bool{}
	for _, in := range cfg.Providers {
		name := strings.TrimSpace(in.Name)
		if name == "" || len(name) > 32 || !safeName(name) {
			return nil, fmt.Errorf("bundle provider %q needs a 1–32 character name of letters, digits, dot, dash or underscore", in.Name)
		}
		if seen[name] {
			return nil, fmt.Errorf("bundle provider %q is listed twice", name)
		}
		seen[name] = true
		p := &provider{name: name, url: strings.TrimSpace(in.URL)}
		if raw := strings.TrimSpace(in.PublicKey); raw != "" {
			pub, err := ParsePublicKey(raw)
			if err != nil {
				return nil, fmt.Errorf("bundle provider %s: %w", name, err)
			}
			p.pub = pub
			p.keyID = KeyID(pub)
		}
		if p.url != "" {
			u, err := url.Parse(p.url)
			if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				return nil, fmt.Errorf("bundle provider %s: URL must be an absolute http or https URL", name)
			}
		}
		m.providers = append(m.providers, p)
	}
	if m.dir != "" {
		if err := os.MkdirAll(m.dir, 0o750); err != nil {
			return nil, fmt.Errorf("create bundle dir: %w", err)
		}
	}
	return m, nil
}

// Enabled reports whether any provider can fetch. Without a signed URL and a
// publisher key the manager only serves packs already installed.
func (m *Manager) Enabled() bool {
	if m == nil {
		return false
	}
	for _, p := range m.providers {
		if p.configured() {
			return true
		}
	}
	return false
}

// HasProvider reports whether name is one of the configured providers, so the
// API can tell an unknown name from a channel that is merely switched off.
func (m *Manager) HasProvider(name string) bool {
	if m == nil {
		return false
	}
	for _, p := range m.providers {
		if p.name == name {
			return true
		}
	}
	return false
}

// OnChange registers the callback that recompiles the WAF engines. It is
// called after a pack is installed, outside the manager lock.
func (m *Manager) OnChange(fn func()) {
	m.mu.Lock()
	m.onChange = fn
	m.mu.Unlock()
}

// Load reads the state file and the packs it names. A pack that is missing or
// unreadable is dropped from the state instead of failing startup: the last
// known good version is what keeps the WAF useful.
func (m *Manager) Load() error {
	raw, err := os.ReadFile(m.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read bundle state: %w", err)
	}
	var st state
	if err := json.Unmarshal(raw, &st); err != nil {
		return fmt.Errorf("decode bundle state: %w", err)
	}
	m.mu.Lock()
	m.st = st
	m.migrateLocked()
	for _, p := range m.providers {
		if ps, ok := m.st.Providers[p.name]; ok && ps != nil {
			p.st = *ps
		}
	}
	kept := make([]bundleState, 0, len(m.st.Bundles))
	for _, b := range m.st.Bundles {
		pack, err := m.readPack(b.Name, b.Version)
		if err != nil {
			m.log.Warn("installed bundle unreadable; dropping it from state", "bundle", b.Name, "err", err)
			continue
		}
		if pack.Bundle != b.Name || pack.Version != b.Version {
			m.log.Warn("installed bundle disagrees with state; dropping it", "bundle", b.Name)
			continue
		}
		kept = append(kept, b)
	}
	m.st.Bundles = kept
	m.rebuildLocked()
	m.mu.Unlock()
	return nil
}

// migrateLocked folds a state file written before providers existed into the
// first configured provider, and names the legacy packs, so an upgrade keeps
// the installed bundle and its anti-rollback sequence.
func (m *Manager) migrateLocked() {
	if m.st.Providers == nil {
		m.st.Providers = map[string]*providerState{}
	}
	legacy := m.st.Sequence > 0 || m.st.ETag != "" || m.st.LastCheck != nil || m.st.LastError != ""
	if legacy && len(m.providers) > 0 {
		first := m.providers[0]
		if _, ok := m.st.Providers[first.name]; !ok {
			m.st.Providers[first.name] = &providerState{
				Sequence: m.st.Sequence, ETag: m.st.ETag,
				LastCheck: m.st.LastCheck, LastError: m.st.LastError,
			}
		}
	}
	m.st.Sequence, m.st.ETag, m.st.LastCheck, m.st.LastError = 0, "", nil, ""
	if len(m.providers) > 0 {
		for i := range m.st.Bundles {
			if m.st.Bundles[i].Provider == "" {
				m.st.Bundles[i].Provider = m.providers[0].name
			}
		}
	}
}

// Start refreshes once and then on the configured interval. A failure is
// logged and retried next tick; the installed packs keep serving.
func (m *Manager) Start(ctx context.Context) {
	if !m.Enabled() {
		return
	}
	go func() {
		if err := m.Check(ctx); err != nil {
			m.log.Warn("bundle channel check failed", "err", err)
		}
		t := time.NewTicker(m.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := m.Check(ctx); err != nil {
					m.log.Warn("bundle channel check failed", "err", err)
				}
			}
		}
	}()
}

// Check refreshes every configured provider. Each one is fetched, verified
// and installed on its own, so an unreachable publisher is reported for that
// provider and the others still update.
func (m *Manager) Check(ctx context.Context) error {
	if m == nil || !m.Enabled() {
		return errors.New("no bundle channel is configured")
	}
	errs := make([]error, 0, len(m.providers))
	for _, p := range m.providers {
		if !p.configured() {
			continue
		}
		if err := m.checkProvider(ctx, p); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.name, err))
		}
	}
	return errors.Join(errs...)
}

// CheckProvider refreshes one named provider, which is what the console's
// per-provider button asks for.
func (m *Manager) CheckProvider(ctx context.Context, name string) error {
	if m == nil {
		return errors.New("no bundle channel is configured")
	}
	for _, p := range m.providers {
		if p.name != name {
			continue
		}
		if !p.configured() {
			return fmt.Errorf("bundle provider %s is not configured", name)
		}
		return m.checkProvider(ctx, p)
	}
	return fmt.Errorf("bundle provider %s is not configured", name)
}

// checkProvider fetches one manifest and installs any bundle whose version
// changed. It is safe to call from the API and the ticker at the same time.
func (m *Manager) checkProvider(ctx context.Context, p *provider) error {
	if !p.checking.CompareAndSwap(false, true) {
		return errors.New("a bundle check is already running")
	}
	defer p.checking.Store(false)

	manifest, notModified, err := m.fetchManifest(ctx, p)
	now := m.now().UTC()
	m.mu.Lock()
	p.st.LastCheck = &now
	m.mu.Unlock()
	if err != nil {
		m.recordError(p, err)
		return err
	}
	// 304 means the sequence and the installed packs are already current.
	// Writing the zero-value manifest would reset the sequence and let a
	// mirror roll the channel back afterwards.
	if notModified {
		m.mu.Lock()
		p.st.LastError = ""
		err := m.saveLocked()
		m.mu.Unlock()
		return err
	}
	m.mu.RLock()
	changed := manifest.Sequence > p.st.Sequence
	m.mu.RUnlock()

	var firstErr error
	for _, ref := range manifest.Bundles {
		if err := m.install(ctx, p, ref); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			m.log.Warn("bundle install failed; keeping the installed version", "provider", p.name, "bundle", ref.Name, "err", err)
			continue
		}
		if m.installedVersion(p, ref.Name) != ref.Version {
			changed = true
		}
	}

	m.mu.Lock()
	p.st.Sequence = manifest.Sequence
	if firstErr != nil {
		p.st.LastError = firstErr.Error()
	} else {
		p.st.LastError = ""
	}
	m.rebuildLocked()
	fn := m.onChange
	persistErr := m.saveLocked()
	m.mu.Unlock()

	if persistErr != nil && firstErr == nil {
		firstErr = persistErr
	}
	if changed && fn != nil {
		fn()
	}
	return firstErr
}

// Rules returns the installed packs in a stable order. The slice is replaced
// after an install, never mutated in place, so a caller may keep it.
func (m *Manager) Rules() []waf.Bundle {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.packs
}

// RuleIndex maps every installed rule ID to its pack.
func (m *Manager) RuleIndex() map[int]RuleInfo {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[int]RuleInfo, len(m.index))
	for id, info := range m.index {
		out[id] = info
	}
	return out
}

// Status reports every provider and every installed pack.
func (m *Manager) Status() Status {
	if m == nil {
		return Status{Providers: []ProviderStatus{}, Bundles: []BundleStatus{}}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	st := Status{
		Providers: make([]ProviderStatus, 0, len(m.providers)),
		Bundles:   make([]BundleStatus, 0, len(m.st.Bundles)),
	}
	for _, p := range m.providers {
		ps := ProviderStatus{
			Name: p.name, Configured: p.configured(), URL: p.url, KeyID: p.keyID,
			Sequence: p.st.Sequence, Error: p.st.LastError,
		}
		if p.st.LastCheck != nil {
			last := *p.st.LastCheck
			next := last.Add(m.interval)
			ps.LastCheck = &last
			ps.NextCheck = &next
		}
		st.Providers = append(st.Providers, ps)
	}
	for _, b := range m.st.Bundles {
		at := b.InstalledAt
		st.Bundles = append(st.Bundles, BundleStatus{
			Provider: b.Provider, Name: b.Name, Version: b.Version, Rules: b.Rules, Size: b.Size,
			SHA256: b.SHA256, InstalledAt: &at,
		})
	}
	sort.Slice(st.Bundles, func(i, j int) bool {
		if st.Bundles[i].Provider != st.Bundles[j].Provider {
			return st.Bundles[i].Provider < st.Bundles[j].Provider
		}
		return st.Bundles[i].Name < st.Bundles[j].Name
	})
	return st
}

// fetchManifest returns the decoded manifest and whether the server answered
// 304, which is the steady state of an hourly check.
func (m *Manager) fetchManifest(ctx context.Context, p *provider) (Manifest, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return Manifest{}, false, err
	}
	req.Header.Set("User-Agent", "wafproxy-bundles/1.0")
	m.mu.RLock()
	etag, seq := p.st.ETag, p.st.Sequence
	m.mu.RUnlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return Manifest{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return Manifest{}, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return Manifest{}, false, fmt.Errorf("manifest http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	if err != nil {
		return Manifest{}, false, err
	}
	if len(body) > maxManifestBytes {
		return Manifest{}, false, errors.New("manifest is larger than the size cap")
	}
	manifest, err := ParseManifest(body, p.pub)
	if err != nil {
		return Manifest{}, false, err
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, false, err
	}
	if manifest.Sequence < seq {
		return Manifest{}, false, fmt.Errorf("manifest sequence %d is older than the installed %d", manifest.Sequence, seq)
	}
	if et := resp.Header.Get("ETag"); et != "" {
		m.mu.Lock()
		p.st.ETag = et
		m.mu.Unlock()
	}
	return manifest, false, nil
}

// install downloads one advertised version unless it is already on disk with
// the advertised checksum.
func (m *Manager) install(ctx context.Context, p *provider, ref Ref) error {
	if m.installedVersion(p, ref.Name) == ref.Version && m.installedSHA(p, ref.Name) == ref.SHA256 {
		return nil
	}
	base, err := url.Parse(p.url)
	if err != nil {
		return err
	}
	packURL, err := base.Parse(ref.Path)
	if err != nil {
		return err
	}
	if packURL.Scheme != "http" && packURL.Scheme != "https" {
		return fmt.Errorf("pack %s has an unsupported scheme", ref.Name)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, packURL.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "wafproxy-bundles/1.0")
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pack http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPackBytes+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > maxPackBytes {
		return errors.New("pack is larger than the size cap")
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != ref.SHA256 {
		return errors.New("pack checksum does not match the manifest")
	}
	var pack Pack
	if err := json.Unmarshal(body, &pack); err != nil {
		return fmt.Errorf("decode pack: %w", err)
	}
	if pack.Bundle != ref.Name || pack.Version != ref.Version {
		return errors.New("pack does not match the manifest entry")
	}
	if len(pack.Rules) != ref.Rules {
		return fmt.Errorf("pack has %d rules, manifest says %d", len(pack.Rules), ref.Rules)
	}
	if err := waf.ValidateBundle(waf.Bundle{Name: pack.Bundle, Version: pack.Version, Rules: pack.Rules}); err != nil {
		return err
	}
	// A pack that cannot compile must never replace a working one.
	if err := waf.ValidateCompile(pack.Bundle, pack.Rules); err != nil {
		return err
	}

	dir := m.packDir(ref.Name, ref.Version)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".pack-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(dir, "pack.json")); err != nil {
		os.Remove(tmpName)
		return err
	}

	m.mu.Lock()
	replaced := false
	for i := range m.st.Bundles {
		// A name belongs to one provider: profiles switch a bundle by name,
		// so two publishers may not install the same one.
		if m.st.Bundles[i].Name == ref.Name && m.st.Bundles[i].Provider != p.name {
			owner := m.st.Bundles[i].Provider
			m.mu.Unlock()
			return fmt.Errorf("bundle %s is already provided by %s", ref.Name, owner)
		}
		if m.st.Bundles[i].Name == ref.Name {
			m.st.Bundles[i] = bundleState{
				Provider: p.name, Name: ref.Name, Version: ref.Version, Rules: ref.Rules, Size: int64(len(body)),
				SHA256: ref.SHA256, InstalledAt: m.now().UTC(),
			}
			replaced = true
			break
		}
	}
	if !replaced {
		m.st.Bundles = append(m.st.Bundles, bundleState{
			Provider: p.name, Name: ref.Name, Version: ref.Version, Rules: ref.Rules, Size: int64(len(body)),
			SHA256: ref.SHA256, InstalledAt: m.now().UTC(),
		})
	}
	m.rebuildLocked()
	m.mu.Unlock()

	m.prune(ref.Name, ref.Version)
	return nil
}

func (m *Manager) recordError(p *provider, err error) {
	m.mu.Lock()
	p.st.LastError = err.Error()
	_ = m.saveLocked()
	m.mu.Unlock()
}

// rebuildLocked recomputes the compiled view and the rule index. Callers hold
// the write lock.
func (m *Manager) rebuildLocked() {
	packs := make([]waf.Bundle, 0, len(m.st.Bundles))
	index := map[int]RuleInfo{}
	states := append([]bundleState(nil), m.st.Bundles...)
	sort.Slice(states, func(i, j int) bool { return states[i].Name < states[j].Name })
	for _, b := range states {
		pack, err := m.readPack(b.Name, b.Version)
		if err != nil {
			m.log.Warn("installed bundle unreadable", "bundle", b.Name, "err", err)
			continue
		}
		packs = append(packs, waf.Bundle{Name: pack.Bundle, Version: pack.Version, Rules: pack.Rules})
		for _, r := range pack.Rules {
			index[r.ID] = RuleInfo{Provider: b.Provider, Bundle: pack.Bundle, Version: pack.Version, Message: r.Message}
		}
	}
	m.packs = packs
	m.index = index
}

func (m *Manager) saveLocked() error {
	if m.dir == "" {
		return nil
	}
	m.syncProvidersLocked()
	raw, err := json.MarshalIndent(m.st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(m.dir, ".state-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, m.statePath()); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// syncProvidersLocked copies each provider's live state into the document
// about to be written, so a save never drops a sequence.
func (m *Manager) syncProvidersLocked() {
	if m.st.Providers == nil {
		m.st.Providers = map[string]*providerState{}
	}
	for _, p := range m.providers {
		ps := p.st
		m.st.Providers[p.name] = &ps
	}
}

func (m *Manager) readPack(name, version string) (Pack, error) {
	raw, err := os.ReadFile(filepath.Join(m.packDir(name, version), "pack.json"))
	if err != nil {
		return Pack{}, err
	}
	var pack Pack
	if err := json.Unmarshal(raw, &pack); err != nil {
		return Pack{}, err
	}
	return pack, nil
}

// prune keeps the installed version plus the previous one, so a bad pack can
// be rolled back by reinstalling rather than redownloading history.
func (m *Manager) prune(name, keep string) {
	entries, err := os.ReadDir(filepath.Join(m.dir, name))
	if err != nil {
		return
	}
	var versions []string
	for _, e := range entries {
		if e.IsDir() {
			versions = append(versions, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(versions)))
	kept := 0
	for _, v := range versions {
		// The installed version counts against the budget like any other, so
		// the previous one has to fit alongside it. Counting it separately
		// would delete the last known good pack.
		if v == keep || kept < keepVersions {
			kept++
			continue
		}
		if err := os.RemoveAll(filepath.Join(m.dir, name, v)); err != nil {
			m.log.Warn("prune bundle version", "bundle", name, "version", v, "err", err)
		}
	}
}

func (m *Manager) installedVersion(p *provider, name string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, b := range m.st.Bundles {
		if b.Name == name && b.Provider == p.name {
			return b.Version
		}
	}
	return ""
}

func (m *Manager) installedSHA(p *provider, name string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, b := range m.st.Bundles {
		if b.Name == name && b.Provider == p.name {
			return b.SHA256
		}
	}
	return ""
}

func (m *Manager) statePath() string {
	return filepath.Join(m.dir, "state.json")
}

func (m *Manager) packDir(name, version string) string {
	return filepath.Join(m.dir, safeSegment(name), safeSegment(version))
}

// safeName reports whether a value survives safeSegment unchanged, which is
// what keeps two packs from sharing a directory.
func safeName(v string) bool { return v != "" && safeSegment(v) == v }

// safeSegment keeps a bundle name or version inside the data directory.
func safeSegment(v string) string {
	var b strings.Builder
	for _, r := range v {
		if r == '.' || r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func validateManifest(m Manifest) error {
	if m.Sequence <= 0 {
		return errors.New("manifest has no sequence")
	}
	if len(m.Bundles) > maxBundles {
		return fmt.Errorf("manifest lists more than %d bundles", maxBundles)
	}
	seen := map[string]bool{}
	for _, ref := range m.Bundles {
		if ref.Name == "" || len(ref.Name) > 64 {
			return errors.New("manifest has a bundle name outside 1–64 characters")
		}
		if seen[ref.Name] {
			return fmt.Errorf("manifest lists %s twice", ref.Name)
		}
		seen[ref.Name] = true
		if ref.Version == "" || len(ref.Version) > 64 {
			return fmt.Errorf("%s has no usable version", ref.Name)
		}
		// The name and version become directory names, so anything that would
		// be rewritten (or could leave the data directory) is refused here.
		if !safeName(ref.Name) || !safeName(ref.Version) {
			return fmt.Errorf("%s has characters outside letters, digits, dot, dash and underscore", ref.Name)
		}
		if ref.Rules <= 0 || ref.Rules > maxRulesPerPack {
			return fmt.Errorf("%s advertises an impossible rule count", ref.Name)
		}
		if ref.Size <= 0 || ref.Size > maxPackBytes {
			return fmt.Errorf("%s advertises an impossible size", ref.Name)
		}
		if len(ref.SHA256) != 64 {
			return fmt.Errorf("%s has no sha256", ref.Name)
		}
		if _, err := hex.DecodeString(ref.SHA256); err != nil {
			return fmt.Errorf("%s has a malformed sha256", ref.Name)
		}
		if ref.Path == "" {
			return fmt.Errorf("%s has no pack path", ref.Name)
		}
	}
	return nil
}
