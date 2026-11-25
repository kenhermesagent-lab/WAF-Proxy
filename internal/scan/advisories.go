package scan

// advisories.go queries OSV for the components the fingerprint stage identified
// and joins the answers to the KEV snapshot. It is the part that turns "the app
// is on version X" into "X matches a vulnerability that is being exploited, so
// patch or compensate now".
//
// Nothing here guesses. A missing or stale source makes the answer unknown, and
// a lookup failure makes it unknown: "no known vulnerabilities" is only said
// when a fresh source actually said so.

import (
	"bytes"
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/updates"
)

const (
	// OSVSource names the advisory source in the feed state.
	OSVSource = "osv"
	// OSVURL is the OSV API root.
	OSVURL            = "https://api.osv.dev"
	osvCacheCap       = 8 << 20
	osvMaxBytes       = 4 << 20
	advisoryTTL       = 7 * 24 * time.Hour
	advisoriesPerItem = 8
)

// Exploitation values answer the only question that changes urgency.
const (
	ExploitationKEV     = "kev"
	ExploitationNone    = "none"
	ExploitationUnknown = "unknown"
)

// Advisory is one OSV advisory reduced to what a finding needs.
type Advisory struct {
	ID        string    `json:"id"`
	Aliases   []string  `json:"aliases,omitempty"`
	Summary   string    `json:"summary,omitempty"`
	CVSS      float64   `json:"cvss,omitempty"`
	Vector    string    `json:"vector,omitempty"`
	Published time.Time `json:"published,omitempty"`
}

// CVEIDs returns the CVE identifiers the advisory is known by.
func (a Advisory) CVEIDs() []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range append([]string{a.ID}, a.Aliases...) {
		id = strings.ToUpper(strings.TrimSpace(id))
		if !strings.HasPrefix(id, "CVE-") || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// AdvisorySource answers for one package at one exact version.
type AdvisorySource interface {
	Advisories(ctx context.Context, pkg, ecosystem, version string) ([]Advisory, error)
}

// OSVCache keeps advisory answers and evicts the least recently used entries
// until it is back under its byte cap. The cap is what keeps the feature inside
// its storage budget; the cache is memory and never unbounded.
type OSVCache struct {
	mu      sync.Mutex
	limit   int64
	used    int64
	entries map[string]*list.Element
	order   *list.List
	now     func() time.Time
	ttl     time.Duration
}

type osvCacheEntry struct {
	key     string
	bytes   []byte
	values  []Advisory
	expires time.Time
}

// NewOSVCache returns a cache with the given byte cap. Zero uses the shipped cap.
func NewOSVCache(limit int64) *OSVCache {
	if limit <= 0 {
		limit = osvCacheCap
	}
	return &OSVCache{
		limit: limit, entries: map[string]*list.Element{}, order: list.New(),
		now: time.Now, ttl: advisoryTTL,
	}
}

// Bytes is the cache's current size.
func (c *OSVCache) Bytes() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.used
}

// Len is the number of cached answers.
func (c *OSVCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *OSVCache) get(key string) ([]Advisory, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	item := el.Value.(*osvCacheEntry)
	if c.now().After(item.expires) {
		c.drop(el)
		return nil, false
	}
	c.order.MoveToFront(el)
	return append([]Advisory(nil), item.values...), true
}

func (c *OSVCache) put(key string, values []Advisory) {
	raw, err := json.Marshal(values)
	if err != nil {
		return
	}
	size := int64(len(raw))
	if size > c.limit {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[key]; ok {
		c.drop(el)
	}
	el := c.order.PushFront(&osvCacheEntry{key: key, bytes: raw, values: values, expires: c.now().Add(c.ttl)})
	c.entries[key] = el
	c.used += size
	for c.used > c.limit {
		last := c.order.Back()
		if last == nil {
			break
		}
		c.drop(last)
	}
}

func (c *OSVCache) drop(el *list.Element) {
	item := el.Value.(*osvCacheEntry)
	c.order.Remove(el)
	delete(c.entries, item.key)
	c.used -= int64(len(item.bytes))
}

// OSV is the advisory client. It refuses a plain-http endpoint so an advisory
// answer cannot be fetched over a channel anyone on the path can rewrite.
type OSV struct {
	BaseURL string
	Client  *http.Client
	Cache   *OSVCache
}

// NewOSV returns a client pointed at the public OSV API. A redirect to another
// host is refused: the answer must come from the source the node meant to ask.
func NewOSV() *OSV {
	return &OSV{
		BaseURL: OSVURL,
		Client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > 0 && !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
					return fmt.Errorf("refusing a cross-host redirect to %s", req.URL.Host)
				}
				return nil
			},
		},
		Cache: NewOSVCache(osvCacheCap),
	}
}

// Advisories queries OSV for one exact package version and caches the answer.
func (o *OSV) Advisories(ctx context.Context, pkg, ecosystem, version string) ([]Advisory, error) {
	base := strings.TrimRight(o.BaseURL, "/")
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("the OSV endpoint must be an https URL, got %q", o.BaseURL)
	}
	if o.Cache == nil {
		o.Cache = NewOSVCache(osvCacheCap)
	}
	version = normalizeVersion(ecosystem, version)
	key := ecosystem + "/" + pkg + "@" + version
	if cached, ok := o.Cache.get(key); ok {
		return cached, nil
	}
	body, err := json.Marshal(map[string]any{
		"package": map[string]string{"name": pkg, "ecosystem": ecosystem},
		"version": version,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := o.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OSV query: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV query returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, osvMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read the OSV answer: %w", err)
	}
	if len(raw) > osvMaxBytes {
		return nil, fmt.Errorf("the OSV answer is larger than %d MB", osvMaxBytes>>20)
	}
	advisories, err := parseOSV(raw)
	if err != nil {
		return nil, err
	}
	o.Cache.put(key, advisories)
	return advisories, nil
}

// normalizeVersion puts the version in the form the ecosystem's advisories use.
// OSV's Go ranges are semantic versions, which carry the leading v; an
// unprefixed version can match no range and look clean.
func normalizeVersion(ecosystem, version string) string {
	version = strings.TrimSpace(version)
	if !strings.EqualFold(ecosystem, "Go") || version == "" {
		return version
	}
	if version[0] >= '0' && version[0] <= '9' {
		return "v" + version
	}
	return version
}

func parseOSV(raw []byte) ([]Advisory, error) {
	var doc struct {
		Vulns []struct {
			ID        string   `json:"id"`
			Aliases   []string `json:"aliases"`
			Summary   string   `json:"summary"`
			Details   string   `json:"details"`
			Published string   `json:"published"`
			Severity  []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
		} `json:"vulns"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode the OSV answer: %w", err)
	}
	out := make([]Advisory, 0, len(doc.Vulns))
	seen := map[string]bool{}
	for _, v := range doc.Vulns {
		id := strings.TrimSpace(v.ID)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		a := Advisory{ID: id, Aliases: v.Aliases, Summary: summaryOf(v.Summary, v.Details)}
		for _, s := range v.Severity {
			if !strings.EqualFold(strings.TrimSpace(s.Type), "CVSS_V3") {
				continue
			}
			vector := strings.TrimSpace(s.Score)
			if score, ok := updates.CVSSv3Score(vector); ok {
				a.CVSS, a.Vector = score, vector
				break
			}
		}
		if published, err := time.Parse(time.RFC3339, strings.TrimSpace(v.Published)); err == nil {
			a.Published = published
		}
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CVSS != out[j].CVSS {
			return out[i].CVSS > out[j].CVSS
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > advisoriesPerItem {
		out = out[:advisoriesPerItem]
	}
	return out, nil
}

func summaryOf(summary, details string) string {
	text := strings.TrimSpace(summary)
	if text == "" {
		text = strings.TrimSpace(details)
	}
	text = strings.Join(strings.Fields(text), " ")
	const limit = 260
	if len(text) > limit {
		text = strings.TrimSpace(text[:limit]) + "…"
	}
	return text
}

// Intel is what the CVE join needs. Both halves are optional, and a missing
// half makes the answer unknown rather than clean.
type Intel struct {
	KEV        *KEV
	Advisories AdvisorySource
	Now        func() time.Time
}

// JoinReport says what the join could and could not establish.
type JoinReport struct {
	Components int      `json:"components"`
	Advisories int      `json:"advisories"`
	KEV        int      `json:"kev"`
	Unknown    bool     `json:"unknown"`
	Reasons    []string `json:"reasons,omitempty"`
}

// Join matches every identified component against OSV and the KEV snapshot.
// Only components the signature table maps to an OSV package are queried; the
// rest are fingerprinted but not assessed, and say so through the reasons.
func (in Intel) Join(ctx context.Context, comps []Component) ([]model.ScanFinding, JoinReport) {
	report := JoinReport{Components: len(comps)}
	now := time.Now()
	if in.Now != nil {
		now = in.Now()
	}
	exploitation := ExploitationNone
	switch {
	case in.KEV == nil:
		exploitation = ExploitationUnknown
		report.Reasons = append(report.Reasons, "no KEV snapshot is loaded")
	case in.KEV.Stale(now):
		exploitation = ExploitationUnknown
		report.Reasons = append(report.Reasons, "the KEV snapshot is stale, so exploitation status is unknown")
	}
	if exploitation == ExploitationUnknown {
		report.Unknown = true
	}
	if len(comps) == 0 {
		report.Unknown = true
		report.Reasons = append(report.Reasons, "no component was identified")
		return nil, report
	}
	if in.Advisories == nil {
		report.Unknown = true
		report.Reasons = append(report.Reasons, "no advisory source is configured")
		return nil, report
	}

	var out []model.ScanFinding
	for _, c := range comps {
		if c.Package == "" || c.Ecosystem == "" || c.Version == "" {
			report.Reasons = append(report.Reasons, fmt.Sprintf(
				"%s has no OSV package mapping, so its advisories were not checked", c.Label))
			report.Unknown = true
			continue
		}
		advisories, err := in.Advisories.Advisories(ctx, c.Package, c.Ecosystem, c.Version)
		if err != nil {
			report.Unknown = true
			report.Reasons = append(report.Reasons, fmt.Sprintf("%s %s: %s", c.Label, c.Version, shortError(err)))
			out = append(out, model.ScanFinding{
				Key: "cve:" + c.Product + ":unknown", Stage: StageBackend, Class: "cve",
				Title:    c.Label + " " + c.Version + " could not be checked for advisories",
				Severity: SeverityUnknown, Exploitation: ExploitationUnknown,
				Product: c.Product, Version: c.Version, Recommendation: "patch",
				Note: "the advisory lookup failed; this is unknown, not clean",
			})
			continue
		}
		if len(advisories) == 0 {
			// An empty answer cannot be told apart from a package name or version
			// OSV does not know, so it is unknown, never clean.
			report.Unknown = true
			report.Reasons = append(report.Reasons, fmt.Sprintf(
				"%s %s: OSV returned no advisory, which cannot be told apart from a package or version OSV does not know, so this is unknown, not clean",
				c.Label, c.Version))
			continue
		}
		for _, a := range advisories {
			report.Advisories++
			entry, exploited := in.KEV.Match(a.CVEIDs())
			state := exploitation
			if exploited {
				state = ExploitationKEV
				report.KEV++
			}
			severity := severityFor(a.CVSS, exploited)
			cves := a.CVEIDs()
			out = append(out, model.ScanFinding{
				Key:      "cve:" + primaryID(a.ID, cves) + ":" + c.Product,
				Stage:    StageBackend,
				Class:    "cve",
				Title:    c.Label + " " + c.Version + " matches " + a.ID,
				Severity: severity,
				CVSS:     a.CVSS,
				// The exploitation answer is what decides urgency, and it is
				// never set from a stale or missing source.
				Exploitation:   state,
				CVEIDs:         cves,
				Product:        c.Product,
				Version:        c.Version,
				Recommendation: "patch",
				Note:           advisoryNote(a, entry, state),
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if severityRankOf(out[i].Severity) != severityRankOf(out[j].Severity) {
			return severityRankOf(out[i].Severity) > severityRankOf(out[j].Severity)
		}
		return out[i].Key < out[j].Key
	})
	return out, report
}

func advisoryNote(a Advisory, entry KEVEntry, state string) string {
	switch state {
	case ExploitationKEV:
		return fmt.Sprintf("%s; added to CISA KEV on %s (%s). Patch now, or compensate with the access gate until the upgrade lands",
			a.Summary, entry.DateAdded, entry.Name)
	case ExploitationUnknown:
		return a.Summary + "; the KEV snapshot cannot say whether this is exploited now, so treat it as urgent: patch or compensate"
	}
	return a.Summary + "; not in the KEV snapshot: patch when the advisory's fix is available"
}

func primaryID(id string, cves []string) string {
	if len(cves) > 0 {
		return cves[0]
	}
	return id
}

func severityFor(cvss float64, exploited bool) string {
	switch {
	case exploited && cvss >= 9:
		return SeverityCritical
	case exploited:
		return SeverityHigh
	case cvss >= 9:
		return SeverityCritical
	case cvss >= 7:
		return SeverityHigh
	case cvss >= 4:
		return SeverityMedium
	case cvss > 0:
		return SeverityLow
	}
	// A fresh advisory with no parseable score is still a finding, but its
	// severity is not something to invent.
	return SeverityUnknown
}

func severityRankOf(severity string) int {
	switch severity {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}
