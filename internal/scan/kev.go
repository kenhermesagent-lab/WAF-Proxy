package scan

// kev.go keeps the CISA known-exploited-vulnerabilities snapshot. It is the only
// source that turns an advisory into "being exploited right now", so its
// freshness matters: a snapshot past three times its daily cadence makes every
// exploitation answer unknown, and a failed refresh keeps the last good data
// instead of reporting no known vulnerabilities.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

const (
	// KEVSource names the snapshot in the feed state and the store.
	KEVSource = "kev"
	// KEVURL is CISA's known-exploited list.
	KEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	// KEVStaleAfter is three times the daily cadence.
	KEVStaleAfter = 72 * time.Hour
	kevMaxBytes   = 8 << 20
)

// KEVEntry is one known-exploited vulnerability, reduced to what a finding says.
type KEVEntry struct {
	CVEID      string `json:"cve_id"`
	Vendor     string `json:"vendor,omitempty"`
	Product    string `json:"product,omitempty"`
	Name       string `json:"name,omitempty"`
	DateAdded  string `json:"date_added,omitempty"`
	DueDate    string `json:"due_date,omitempty"`
	Ransomware string `json:"ransomware,omitempty"`
}

// KEV is one parsed snapshot. raw is the exact body the hash was taken over, so
// what the page shows and what the node matched cannot drift apart.
type KEV struct {
	FetchedAt time.Time
	ETag      string
	SHA256    string
	Entries   map[string]KEVEntry
	raw       []byte
}

// Stale reports whether the snapshot is too old to answer an exploitation
// question. A missing snapshot is stale.
func (k *KEV) Stale(now time.Time) bool {
	return k == nil || k.FetchedAt.IsZero() || now.Sub(k.FetchedAt) > KEVStaleAfter
}

// Len is the number of entries the snapshot holds.
func (k *KEV) Len() int {
	if k == nil {
		return 0
	}
	return len(k.Entries)
}

// Match reports whether any of ids is in the snapshot.
func (k *KEV) Match(ids []string) (KEVEntry, bool) {
	if k == nil {
		return KEVEntry{}, false
	}
	for _, id := range ids {
		if entry, ok := k.Entries[strings.ToUpper(strings.TrimSpace(id))]; ok {
			return entry, true
		}
	}
	return KEVEntry{}, false
}

// KEVClient fetches and validates the snapshot.
type KEVClient struct {
	URL    string
	Client *http.Client
	Now    func() time.Time
}

// NewKEVClient returns a client that refuses cross-host redirects: a redirect is
// how a fetch meant for one host ends up reading another's answer.
func NewKEVClient() *KEVClient {
	return &KEVClient{
		URL: KEVURL,
		Client: &http.Client{
			Timeout: 90 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > 0 && !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
					return fmt.Errorf("refusing a cross-host redirect to %s", req.URL.Host)
				}
				return nil
			},
		},
		Now: time.Now,
	}
}

// Refresh fetches the snapshot. A 304 moves the confirmation time forward and
// keeps the data; a failed or malformed answer leaves prev untouched, so a bad
// download can never replace a good snapshot.
func (c *KEVClient) Refresh(ctx context.Context, prev *KEV) (*KEV, bool, error) {
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, false, fmt.Errorf("the KEV feed must be an https URL, got %q", c.URL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return nil, false, err
	}
	if prev != nil && prev.ETag != "" {
		req.Header.Set("If-None-Match", prev.ETag)
	}
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("fetch the KEV snapshot: %w", err)
	}
	defer resp.Body.Close()

	now := c.now()
	if resp.StatusCode == http.StatusNotModified && prev != nil {
		fresh := *prev
		fresh.FetchedAt = now
		return &fresh, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("KEV fetch returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, kevMaxBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("read the KEV snapshot: %w", err)
	}
	if len(body) > kevMaxBytes {
		return nil, false, fmt.Errorf("KEV snapshot is larger than %d MB", kevMaxBytes>>20)
	}
	entries, err := parseKEV(body)
	if err != nil {
		return nil, false, err
	}
	sum := sha256.Sum256(body)
	return &KEV{
		FetchedAt: now,
		ETag:      strings.TrimSpace(resp.Header.Get("ETag")),
		SHA256:    hex.EncodeToString(sum[:]),
		Entries:   entries,
		raw:       body,
	}, true, nil
}

// parseKEV validates the whole document before trusting any of it. One entry
// without a CVE id or a date rejects the file, because a partially parsed
// snapshot would silently answer "not exploited" for the rest.
func parseKEV(body []byte) (map[string]KEVEntry, error) {
	var doc struct {
		Count           int `json:"count"`
		Vulnerabilities []struct {
			CVEID                      string `json:"cveID"`
			VendorProject              string `json:"vendorProject"`
			Product                    string `json:"product"`
			VulnerabilityName          string `json:"vulnerabilityName"`
			DateAdded                  string `json:"dateAdded"`
			DueDate                    string `json:"dueDate"`
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("the KEV snapshot is not valid JSON: %w", err)
	}
	if doc.Vulnerabilities == nil {
		return nil, errors.New("the KEV snapshot has no vulnerabilities list")
	}
	if doc.Count != 0 && doc.Count != len(doc.Vulnerabilities) {
		return nil, fmt.Errorf("the KEV snapshot says %d entries but carries %d", doc.Count, len(doc.Vulnerabilities))
	}
	entries := make(map[string]KEVEntry, len(doc.Vulnerabilities))
	for i, v := range doc.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CVEID))
		if !strings.HasPrefix(id, "CVE-") {
			return nil, fmt.Errorf("KEV entry %d has no CVE id", i)
		}
		added := strings.TrimSpace(v.DateAdded)
		if _, err := time.Parse("2006-01-02", added); err != nil {
			return nil, fmt.Errorf("KEV entry %s has no valid dateAdded", id)
		}
		entries[id] = KEVEntry{
			CVEID: id, Vendor: strings.TrimSpace(v.VendorProject), Product: strings.TrimSpace(v.Product),
			Name: strings.TrimSpace(v.VulnerabilityName), DateAdded: added,
			DueDate: strings.TrimSpace(v.DueDate), Ransomware: strings.TrimSpace(v.KnownRansomwareCampaignUse),
		}
	}
	return entries, nil
}

func (c *KEVClient) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Save stores the snapshot so a restart keeps the last good data and the page
// can show exactly what the node believed and when.
func (k *KEV) Save(st *store.Store) error {
	if k == nil || len(k.raw) == 0 {
		return errors.New("scan: refusing to save an empty KEV snapshot")
	}
	return st.SaveVulnSource(store.VulnSource{
		Source: KEVSource, LastOK: k.FetchedAt, ETag: k.ETag, SHA256: k.SHA256,
		Bytes: int64(len(k.raw)), Records: len(k.Entries), Payload: k.raw,
	})
}

// LoadKEV reads the last good snapshot. A snapshot that no longer parses is an
// error, not an empty list.
func LoadKEV(st *store.Store) (*KEV, error) {
	src, err := st.VulnSource(KEVSource)
	if err != nil || src == nil || len(src.Payload) == 0 {
		return nil, err
	}
	entries, err := parseKEV(src.Payload)
	if err != nil {
		return nil, fmt.Errorf("scan: stored KEV snapshot: %w", err)
	}
	sum := sha256.Sum256(src.Payload)
	return &KEV{
		FetchedAt: src.LastOK, ETag: src.ETag,
		SHA256: hex.EncodeToString(sum[:]), Entries: entries, raw: src.Payload,
	}, nil
}
