// Package intel loads open-source threat feeds into memory and exposes a fast
// prefix matcher used by the policy engine.
package intel

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
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
	// Always marks a permanent-ban list, enforced before the allow lists.
	Always bool
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
	always *netmatch.Map[Entry]           // unconditional entries
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
			feed = &storeFeed{name: f.Name, url: f.URL, action: f.Action, localPath: f.LocalPath,
				etag: f.ETag, lastModified: f.LastModified, lastCount: f.LastCount, state: f.State,
				always: f.AlwaysBlock}
			break
		}
	}
	if feed == nil || (feed.url == "" && feed.localPath == "") {
		return
	}
	var count int
	if feed.localPath != "" {
		count, err = m.refreshLocal(id, feed)
	} else {
		count, err = m.fetch(ctx, id, feed)
	}
	if err != nil {
		_ = m.st.UpdateFeedFetch(id, feed.etag, feed.lastModified, feed.lastCount, "error", err.Error())
		m.log.Warn("feed refresh failed", "feed", feed.name, "err", err)
		return
	}
	_ = m.st.UpdateFeedFetch(id, feed.etag, feed.lastModified, count, "ok", "")
}

type storeFeed struct {
	name, url, action, localPath string
	etag, lastModified           string
	lastCount                    int
	state                        string
	always                       bool
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

	parsed, err := Parse(io.LimitReader(resp.Body, m.maxBytes))
	if err != nil {
		return 0, err
	}
	prefixes, skipped := filterPublic(parsed)
	if skipped > 0 {
		m.log.Warn("feed entries skipped as non-public", "feed", f.name, "skipped", skipped)
	}
	count, err := m.applyPrefixes(id, f, prefixes)
	if err != nil {
		return 0, err
	}
	if et := resp.Header.Get("ETag"); et != "" {
		f.etag = et
	}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		f.lastModified = lm
	}
	return count, nil
}

// refreshLocal reads an uploaded blocklist from the data directory. It never
// accepts a path from a request; the path is stored when the file is created.
func (m *Manager) refreshLocal(id int64, f *storeFeed) (int, error) {
	file, err := os.Open(f.localPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	prefixes, err := Parse(io.LimitReader(file, m.maxBytes))
	if err != nil {
		return 0, err
	}
	return m.applyPrefixes(id, f, prefixes)
}

func (m *Manager) applyPrefixes(id int64, f *storeFeed, prefixes []netip.Prefix) (int, error) {
	if len(prefixes) == 0 {
		return 0, errors.New("feed contained no usable entries")
	}

	// Guardrail: a sudden order-of-magnitude growth is treated as poisoning.
	if f.lastCount > 1000 && len(prefixes) > f.lastCount*5 {
		_ = m.st.UpdateFeedFetch(id, f.etag, f.lastModified, f.lastCount, "frozen", "size spike: refusing to apply")
		m.log.Error("feed frozen after size spike", "feed", f.name, "previous", f.lastCount, "new", len(prefixes))
		return f.lastCount, nil
	}

	entry := Entry{FeedID: id, Feed: f.name, Action: normalizeAction(f.action), Always: f.always}
	agg := netmatch.Aggregate(prefixes)
	set := netmatch.New[Entry]()
	for _, p := range agg {
		set.AddPrefix(p, entry)
	}

	m.mu.Lock()
	m.feeds[id] = &feedSet{meta: entry, count: len(agg), set: set}
	m.mu.Unlock()
	return len(agg), nil
}

// rebuild merges every per-feed set into three action-class maps so a request
// costs one lookup per class rather than one per feed.
func (m *Manager) rebuild() {
	merged := map[uint8]*netmatch.Map[Entry]{}
	var byAction = map[string]*netmatch.Map[Entry]{}
	always := netmatch.New[Entry]()
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for _, fs := range m.feeds {
		if fs.meta.Always {
			fs.set.Range(func(p netip.Prefix, e Entry) bool {
				always.AddPrefix(p, e)
				return true
			})
		}
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
	m.always = always
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

// MatchAlways returns a permanent-ban list match. These entries are enforced
// before the allow lists, because a permanent ban is absolute.
func (m *Manager) MatchAlways(addr netip.Addr) (Entry, bool) {
	m.mu.RLock()
	always := m.always
	m.mu.RUnlock()
	if always == nil {
		return Entry{}, false
	}
	e, hit := always.Match(addr)
	if hit {
		m.noteMatch(e.FeedID, addr)
	}
	return e, hit
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

// filterPublic drops loopback, private, link-local, multicast and unspecified
// prefixes from a remote feed: one that lists 10.0.0.0/8 or 169.254.169.254
// would otherwise block the operator's own network or the metadata endpoint.
// Uploaded lists are not filtered here, because blocking a private range on
// purpose is a legitimate choice for a local list.
func filterPublic(prefixes []netip.Prefix) (kept []netip.Prefix, skipped int) {
	kept = make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		a := p.Addr()
		if a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
			a.IsLinkLocalMulticast() || a.IsMulticast() {
			skipped++
			continue
		}
		kept = append(kept, p)
	}
	return kept, skipped
}

// Parse extracts prefixes from common text feed formats.
func Parse(r io.Reader) ([]netip.Prefix, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	out := make([]netip.Prefix, 0, 65536)
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			line = strings.TrimPrefix(line, "\ufeff")
			first = false
		}
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
		// DShield "start end netmask" format must be checked before parsing the
		// first field as a single address, or its start IP becomes a /32.
		if len(fields) >= 3 {
			if _, err := netip.ParseAddr(fields[1]); err == nil {
				if p, ok := dshield(fields[0], fields[2]); ok {
					out = append(out, p)
					continue
				}
			}
		}
		if p, err := netmatch.ParsePrefix(strings.Trim(fields[0], `"'`)); err == nil {
			out = append(out, p)
			continue
		}
	}
	return out, sc.Err()
}

// ParseCSV extracts the first IP or CIDR from each CSV record. Uploaded lists
// commonly put the address in a named column rather than the first one.
func ParseCSV(r io.Reader) ([]netip.Prefix, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	cr.TrimLeadingSpace = true
	out := make([]netip.Prefix, 0, 65536)
	first := true
	for {
		record, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(record) == 0 {
			continue
		}
		if first {
			record[0] = strings.TrimPrefix(record[0], "\ufeff")
			first = false
		}
		cell := strings.TrimSpace(record[0])
		if cell == "" || strings.HasPrefix(cell, "#") || strings.HasPrefix(cell, ";") {
			continue
		}
		// DShield rows are start,end,mask; check them before the general scan
		// turns the start address into a /32.
		if len(record) >= 3 {
			if _, err := netip.ParseAddr(strings.TrimSpace(strings.Trim(record[1], `"'`))); err == nil {
				if p, ok := dshield(strings.TrimSpace(strings.Trim(record[0], `"'`)), strings.TrimSpace(strings.Trim(record[2], `"'`))); ok {
					out = append(out, p)
					continue
				}
			}
		}
		for _, raw := range record {
			value := strings.TrimSpace(raw)
			value = strings.TrimSpace(strings.Trim(value, `"'`))
			if value == "" || strings.HasPrefix(value, "#") || strings.HasPrefix(value, ";") {
				continue
			}
			if p, err := netmatch.ParsePrefix(value); err == nil {
				out = append(out, p)
				break
			}
		}
	}
	return out, nil
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
