package store

import (
	"encoding/json"
	"strconv"
	"time"
)

// encodeBundleModes renders the per-profile bundle modes as the JSON column.
func encodeBundleModes(modes map[string]string) string {
	if len(modes) == 0 {
		return "{}"
	}
	raw, err := json.Marshal(modes)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

// decodeBundleModes tolerates a missing or damaged column: an unreadable value
// means every bundle keeps the default log mode rather than none of them
// blocking silently.
func decodeBundleModes(raw string) map[string]string {
	out := map[string]string{}
	if raw == "" {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

// RuleHit is one signature rule's activity over a window. Blocked and Logged
// are what the requests actually got, which is not the same as what the
// installed profiles would allow: a rule can be logged on a site that blocks
// it and blocked on another.
type RuleHit struct {
	RuleID    int    `json:"rule_id"`
	Hits      int64  `json:"hits"`
	Addresses int64  `json:"addresses"`
	Blocked   int64  `json:"blocked"`
	Logged    int64  `json:"logged"`
	LastSeen  string `json:"last_seen"`
	Message   string `json:"message"`
}

// BundleHits counts the bundle rules that fired since a time. Bundle rule IDs
// live in the reserved 990000–999999 range, above every CRS ID, which is why
// this is a plain query over the existing event log: no extra write path, no
// second source of truth.
func (s *Store) BundleHits(since time.Time) ([]RuleHit, error) {
	rows, err := s.db.Query(`SELECT rule_id, COUNT(*), COUNT(DISTINCT src_ip),
			SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END),
			SUM(CASE WHEN action <> 'block' THEN 1 ELSE 0 END),
			MAX(ts), MAX(rule_msg)
		FROM events
		WHERE ts >= ? AND stage = 'waf' AND LENGTH(rule_id) = 6 AND rule_id >= '990000' AND rule_id <= '999999'
		GROUP BY rule_id
		ORDER BY COUNT(*) DESC
		LIMIT 100`, stamp(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RuleHit{}
	for rows.Next() {
		var h RuleHit
		var rule string
		if err := rows.Scan(&rule, &h.Hits, &h.Addresses, &h.Blocked, &h.Logged, &h.LastSeen, &h.Message); err != nil {
			return nil, err
		}
		id, err := strconv.Atoi(rule)
		if err != nil {
			continue
		}
		h.RuleID = id
		out = append(out, h)
	}
	return out, rows.Err()
}
