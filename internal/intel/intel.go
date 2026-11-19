// Package intel loads open-source threat feeds into memory and exposes a fast
// prefix matcher used by the policy engine.
package intel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/netmatch"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// Entry is the metadata attached to a matched prefix.
type Entry struct {
	FeedID int64
	Feed   string
	Action string
}

// Status is the runtime state of one feed, exposed to the GUI.
type Status struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	Action    string     `json:"action"`
	State     string     `json:"state"`
	Entries   int        `json:"entries"`
	LastFetch *time.Time `json:"last_fetch,omitempty"`
	Error     string     `json:"error,omitempty"`
	Enabled   bool       `json:"enabled"`
}

type feedSet struct {
	meta  Entry
	count int
	set   *netmatch.Map[Entry]
}

// Manager owns the merged in-memory feed table.
type Manager struct {
	st     *store.Store
	client *http.Client
	log    *slog.Logger

	mu     sync.RWMutex
	feeds  map[int64]*feedSet
	merged map[uint8]*netmatch.Map[Entry] // keyed by action class
	total  int

	// guardrails
	distinct map[int64]map[string]struct{}
	guardMu  sync.Mutex
	abuseKey string

	maxBytes int64
	now      func() time.Time
}

const (
	actionBlock     = "block"
	actionChallenge = "challenge"
	actionLog       = "log"
)

// New returns a manager. maxBytes caps a single feed download.
func New(st *store.Store, log *slog.Logger, maxBytes int64) *Manager {
	if maxBytes <= 0 {
		maxBytes = 32 << 20
	}
	return &Manager{
		st:       st,
		log:      log,
		client:   &http.Client{Timeout: 45 * time.Second},
		feeds:    map[int64]*feedSet{},
		merged:   map[uint8]*netmatch.Map[Entry]{},
		distinct: map[int64]map[string]struct{}{},
		maxBytes: maxBytes,
		now:      time.Now,
	}
}

// Start loads cached lists immediately and then refreshes on a schedule.
func (m *Manager) Start(ctx context.Context) {
	m.refreshAll(ctx)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.refreshDue(ctx)
				m.evictDistinct()
			}
		}
	}()
}

func (m *Manager) refreshAll(ctx context.Context) {
	feeds, err := m.st.ListFeeds()
	if err != nil {
		m.log.Error("list feeds", "err", err)
		return
	}
	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup
	for _, f := range feeds {
		if !f.Enabled {
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(feedID int64) {
			defer wg.Done()
			defer func() { <-sem }()
			m.refreshOne(ctx, feedID)
		}(f.ID)
	}
	wg.Wait()
	m.rebuild()
}

func (m *Manager) refreshDue(ctx context.Context) {
	feeds, err := m.st.ListFeeds()
	if err != nil {
		return
	}
	for _, f := range feeds {
		if !f.Enabled || f.State == "frozen" {
			continue
		}
		due := f.LastFetch == nil || m.now().Sub(*f.LastFetch) >= time.Duration(f.IntervalS)*time.Second
		if !due {
			continue
		}
		m.refreshOne(ctx, f.ID)
		m.rebuild()
	}
}

func (m *Manager) refreshOne(ctx context.Context, id int64) {
	feeds, err := m.st.ListFeeds()
	if err != nil {
		return
	}
	var feed *storeFeed
	for _, f := range feeds {
		if f.ID == id {
			feed = &storeFeed{f.Name, f.URL, f.Action, f.ETag, f.LastModified, f.LastCount, f.State}
			break
		}
	}
	if feed == nil || feed.url == "" {
		return
	}
	count, err := m.fetch(ctx, id, feed)
	if err != nil {
		_ = m.st.UpdateFeedFetch(id, feed.etag, feed.lastModified, feed.lastCount, "error", err.Error())
		m.log.Warn("feed refresh failed", "feed", feed.name, "err", err)
		return
	}
	_ = m.st.UpdateFeedFetch(id, feed.etag, feed.lastModified, count, "ok", "")
}

type storeFeed struct {
	name, url, action, etag, lastModified string
	lastCount                             int
	state                                 string
}

func (m *Manager) fetch(ctx context.Context, id int64, f *storeFeed) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "wafproxy-intel/1.0")
	if f.etag != "" {
		req.Header.Set("If-None-Match", f.etag)
	}
	if f.lastModified != "" {
		req.Header.Set("If-Modified-Since", f.lastModified)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		m.mu.RLock()
		defer m.mu.RUnlock()
		if fs, ok := m.feeds[id]; ok {
			return fs.count, nil
		}
		return f.lastCount, nil
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("http %d", resp.StatusCode)
	}

	prefixes, err := parseReader(io.LimitReader(resp.Body, m.maxBytes))
	if err != nil {
		return 0, err
	}
	if len(prefixes) == 0 {
		return 0, errors.New("feed contained no usable entries")
	}

	// Guardrail: a sudden order-of-magnitude growth is treated as poisoning.
	if f.lastCount > 1000 && len(prefixes) > f.lastCount*5 {
		_ = m.st.UpdateFeedFetch(id, resp.Header.Get("ETag"), resp.Header.Get("Last-Modified"),
			f.lastCount, "frozen", "size spike: refusing to apply")
		m.log.Error("feed frozen after size spike", "feed", f.name, "previous", f.lastCount, "new", len(prefixes))
		return f.lastCount, nil
	}

	entry := Entry{FeedID: id, Feed: f.name, Action: normalizeAction(f.action)}
	agg := netmatch.Aggregate(prefixes)
	set := netmatch.New[Entry]()
	for _, p := range agg {
		set.AddPrefix(p, entry)
	}

	m.mu.Lock()
	m.feeds[id] = &feedSet{meta: entry, count: len(agg), set: set}
	m.mu.Unlock()

	if et := resp.Header.Get("ETag"); et != "" {
		f.etag = et
	}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		f.lastModified = lm
	}
	return len(agg), nil
}

// rebuild merges every per-feed set into three action-class maps so a request
// costs one lookup per class rather than one per feed.
func (m *Manager) rebuild() {
	merged := map[uint8]*netmatch.Map[Entry]{}
	var byAction = map[string]*netmatch.Map[Entry]{}
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for _, fs := range m.feeds {
		key := normalizeAction(fs.meta.Action)
		class := actionClass(key)
		mm, ok := byAction[key]
		if !ok {
			mm = netmatch.New[Entry]()
			byAction[key] = mm
		}
		fs.set.Range(func(p netip.Prefix, e Entry) bool {
			mm.AddPrefix(p, e)
			return true
		})
		total += fs.count
		_ = class
	}
	for k, v := range byAction {
		merged[actionClass(k)] = v
	}
	m.merged = merged
	m.total = total
}

func actionClass(action string) uint8 {
	switch action {
	case actionChallenge:
		return 2
	case actionLog:
		return 3
	default:
		return 1
	}
}

func normalizeAction(a string) string {
	switch a {
	case actionChallenge, actionLog, actionBlock:
		return a
	default:
		return actionBlock
	}
}

// Match returns the strongest matching feed entry for an address.
func (m *Manager) Match(addr netip.Addr) (Entry, bool) {
	m.mu.RLock()
	merged := m.merged
	m.mu.RUnlock()
	// Block wins over challenge, challenge over log.
	for _, class := range []uint8{1, 2, 3} {
		if set, ok := merged[class]; ok {
			if e, hit := set.Match(addr); hit {
				m.noteMatch(e.FeedID, addr)
				return e, true
			}
		}
	}
	return Entry{}, false
}

func (m *Manager) noteMatch(feedID int64, addr netip.Addr) {
	m.guardMu.Lock()
	defer m.guardMu.Unlock()
	if m.distinct[feedID] == nil {
		m.distinct[feedID] = map[string]struct{}{}
	}
	if len(m.distinct[feedID]) < 100000 {
		m.distinct[feedID][addr.String()] = struct{}{}
	}
}

func (m *Manager) evictDistinct() {
	m.guardMu.Lock()
	m.distinct = map[int64]map[string]struct{}{}
	m.guardMu.Unlock()
}

// Status returns per-feed state for the Threat Intel page.
func (m *Manager) Status() []Status {
	feeds, err := m.st.ListFeeds()
	if err != nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Status, 0, len(feeds))
	for _, f := range feeds {
		s := Status{
			ID: f.ID, Name: f.Name, Action: f.Action, State: f.State,
			LastFetch: f.LastFetch, Error: f.LastError, Enabled: f.Enabled,
		}
		if fs, ok := m.feeds[f.ID]; ok {
			s.Entries = fs.count
		}
		out = append(out, s)
	}
	return out
}

// Total returns the number of merged prefixes.
func (m *Manager) Total() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.total
}

// Refresh forces a refresh of one feed.
func (m *Manager) Refresh(ctx context.Context, id int64) {
	m.refreshOne(ctx, id)
	m.rebuild()
}

// parseReader extracts prefixes from common feed formats.
func parseReader(r io.Reader) ([]netip.Prefix, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	out := make([]netip.Prefix, 0, 65536)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if p, err := netmatch.ParsePrefix(fields[0]); err == nil {
			out = append(out, p)
			continue
		}
		// DShield "start end netmask" format.
		if len(fields) >= 3 {
			if p, ok := dshield(fields[0], fields[2]); ok {
				out = append(out, p)
			}
		}
	}
	return out, sc.Err()
}

func dshield(start, mask string) (netip.Prefix, bool) {
	m, err := strconv.Atoi(mask)
	if err != nil || m < 0 || m > 32 {
		return netip.Prefix{}, false
	}
	a, err := netip.ParseAddr(start)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a.Unmap(), m).Masked(), true
}
