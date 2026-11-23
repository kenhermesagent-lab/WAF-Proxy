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

// Config describes the channel. An empty URL or public key leaves the channel
// disabled: the manager then serves whatever is already on disk.
type Config struct {
	Dir       string
	URL       string
	PublicKey string
	Interval  time.Duration
	Log       *slog.Logger
}

// Status is the channel as the console shows it.
type Status struct {
	Configured bool           `json:"configured"`
	URL        string         `json:"url,omitempty"`
	KeyID      string         `json:"key_id,omitempty"`
	LastCheck  *time.Time     `json:"last_check,omitempty"`
	NextCheck  *time.Time     `json:"next_check,omitempty"`
	Sequence   int64          `json:"sequence"`
	Error      string         `json:"error,omitempty"`
	Bundles    []BundleStatus `json:"bundles"`
}

// BundleStatus is one installed pack.
type BundleStatus struct {
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
	Bundle  string
	Version string
	Message string
}

type bundleState struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Rules       int       `json:"rules"`
	Size        int64     `json:"size"`
	SHA256      string    `json:"sha256"`
	InstalledAt time.Time `json:"installed_at"`
}

type state struct {
	Sequence  int64         `json:"sequence"`
	ETag      string        `json:"etag,omitempty"`
	LastCheck *time.Time    `json:"last_check,omitempty"`
	LastError string        `json:"last_error,omitempty"`
	Bundles   []bundleState `json:"bundles"`
}

// Manager owns the installed packs and the refresh loop.
type Manager struct {
	dir      string
	url      string
	pub      ed25519.PublicKey
	keyID    string
	interval time.Duration
	log      *slog.Logger
	client   *http.Client
	now      func() time.Time

	mu       sync.RWMutex
	st       state
	packs    []waf.Bundle
	index    map[int]RuleInfo
	onChange func()

	checking atomic.Bool
}

// New validates the configuration and prepares the on-disk layout.
func New(cfg Config) (*Manager, error) {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	m := &Manager{
		dir:      cfg.Dir,
		url:      strings.TrimSpace(cfg.URL),
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
	if raw := strings.TrimSpace(cfg.PublicKey); raw != "" {
		pub, err := ParsePublicKey(raw)
		if err != nil {
			return nil, err
		}
		m.pub = pub
		m.keyID = KeyID(pub)
	}
	if m.dir != "" {
		if err := os.MkdirAll(m.dir, 0o750); err != nil {
			return nil, fmt.Errorf("create bundle dir: %w", err)
		}
	}
	return m, nil
}

// Enabled reports whether the channel can fetch. Without a signed URL and a
// publisher key the manager only serves packs already installed.
func (m *Manager) Enabled() bool {
	return m != nil && m.url != "" && len(m.pub) == ed25519.PublicKeySize
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
	kept := make([]bundleState, 0, len(st.Bundles))
	for _, b := range st.Bundles {
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
	st.Bundles = kept
	m.mu.Lock()
	m.st = st
	m.rebuildLocked()
	m.mu.Unlock()
	return nil
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

// Check fetches the manifest and installs any bundle whose version changed.
// It is safe to call from the API and the ticker at the same time.
func (m *Manager) Check(ctx context.Context) error {
	if !m.Enabled() {
		return errors.New("no bundle channel is configured")
	}
	if !m.checking.CompareAndSwap(false, true) {
		return errors.New("a bundle check is already running")
	}
	defer m.checking.Store(false)

	manifest, notModified, err := m.fetchManifest(ctx)
	now := m.now().UTC()
	m.mu.Lock()
	m.st.LastCheck = &now
	m.mu.Unlock()
	if err != nil {
		m.recordError(err)
		return err
	}
	// 304 means the sequence and the installed packs are already current.
	// Writing the zero-value manifest would reset the sequence and let a
	// mirror roll the channel back afterwards.
	if notModified {
		m.mu.Lock()
		m.st.LastError = ""
		err := m.saveLocked()
		m.mu.Unlock()
		return err
	}
	changed := manifest.Sequence > m.currentSequence()

	var firstErr error
	for _, ref := range manifest.Bundles {
		if err := m.install(ctx, ref); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			m.log.Warn("bundle install failed; keeping the installed version", "bundle", ref.Name, "err", err)
			continue
		}
		if m.installedVersion(ref.Name) != ref.Version {
			changed = true
		}
	}

	m.mu.Lock()
	m.st.Sequence = manifest.Sequence
	if firstErr != nil {
		m.st.LastError = firstErr.Error()
	} else {
		m.st.LastError = ""
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

// Status reports the channel and every installed pack.
func (m *Manager) Status() Status {
	if m == nil {
		return Status{Configured: false, Bundles: []BundleStatus{}}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	st := Status{
		Configured: m.Enabled(),
		URL:        m.url,
		KeyID:      m.keyID,
		Sequence:   m.st.Sequence,
		Error:      m.st.LastError,
		Bundles:    make([]BundleStatus, 0, len(m.st.Bundles)),
	}
	if m.st.LastCheck != nil {
		last := *m.st.LastCheck
		next := last.Add(m.interval)
		st.LastCheck = &last
		st.NextCheck = &next
	}
	for _, b := range m.st.Bundles {
		at := b.InstalledAt
		st.Bundles = append(st.Bundles, BundleStatus{
			Name: b.Name, Version: b.Version, Rules: b.Rules, Size: b.Size,
			SHA256: b.SHA256, InstalledAt: &at,
		})
	}
	sort.Slice(st.Bundles, func(i, j int) bool { return st.Bundles[i].Name < st.Bundles[j].Name })
	return st
}

// fetchManifest returns the decoded manifest and whether the server answered
// 304, which is the steady state of an hourly check.
func (m *Manager) fetchManifest(ctx context.Context) (Manifest, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.url, nil)
	if err != nil {
		return Manifest{}, false, err
	}
	req.Header.Set("User-Agent", "wafproxy-bundles/1.0")
	m.mu.RLock()
	etag := m.st.ETag
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
	manifest, err := ParseManifest(body, m.pub)
	if err != nil {
		return Manifest{}, false, err
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, false, err
	}
	if manifest.Sequence < m.currentSequence() {
		return Manifest{}, false, fmt.Errorf("manifest sequence %d is older than the installed %d", manifest.Sequence, m.currentSequence())
	}
	if et := resp.Header.Get("ETag"); et != "" {
		m.mu.Lock()
		m.st.ETag = et
		m.mu.Unlock()
	}
	return manifest, false, nil
}

// install downloads one advertised version unless it is already on disk with
// the advertised checksum.
func (m *Manager) install(ctx context.Context, ref Ref) error {
	if m.installedVersion(ref.Name) == ref.Version && m.installedSHA(ref.Name) == ref.SHA256 {
		return nil
	}
	base, err := url.Parse(m.url)
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
		if m.st.Bundles[i].Name == ref.Name {
			m.st.Bundles[i] = bundleState{
				Name: ref.Name, Version: ref.Version, Rules: ref.Rules, Size: int64(len(body)),
				SHA256: ref.SHA256, InstalledAt: m.now().UTC(),
			}
			replaced = true
			break
		}
	}
	if !replaced {
		m.st.Bundles = append(m.st.Bundles, bundleState{
			Name: ref.Name, Version: ref.Version, Rules: ref.Rules, Size: int64(len(body)),
			SHA256: ref.SHA256, InstalledAt: m.now().UTC(),
		})
	}
	m.rebuildLocked()
	m.mu.Unlock()

	m.prune(ref.Name, ref.Version)
	return nil
}

func (m *Manager) recordError(err error) {
	m.mu.Lock()
	m.st.LastError = err.Error()
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
			index[r.ID] = RuleInfo{Bundle: pack.Bundle, Version: pack.Version, Message: r.Message}
		}
	}
	m.packs = packs
	m.index = index
}

func (m *Manager) saveLocked() error {
	if m.dir == "" {
		return nil
	}
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

func (m *Manager) currentSequence() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.st.Sequence
}

func (m *Manager) installedVersion(name string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, b := range m.st.Bundles {
		if b.Name == name {
			return b.Version
		}
	}
	return ""
}

func (m *Manager) installedSHA(name string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, b := range m.st.Bundles {
		if b.Name == name {
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
