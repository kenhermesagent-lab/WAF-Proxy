package store

import "time"

// truncate bounds user-supplied text before it is stored. Counted in runes so a
// multi-byte username is never cut mid-character.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// RecordGateFailure logs one failed access-gate login. The username is stored
// as submitted, including unknown accounts: an operator reviewing the page
// needs to see which accounts are being tried. The row is replicated so the
// escalation ladder counts the same attempts after a failover.
func (s *Store) RecordGateFailure(ip string, proxyID int64, username, reason string) error {
	var id int64
	return s.upsertChanged("gate_failures", []string{"id"}, func(db execer) ([]any, error) {
		res, err := db.Exec(`INSERT INTO gate_failures(ip, proxy_id, username, reason, ts, site_id)
			VALUES(?, ?, ?, ?, ?, COALESCE((SELECT site_id FROM proxies WHERE id = ?), ?))`,
			ip, proxyID, truncate(username, 190), truncate(reason, 40), stamp(time.Now()), proxyID, s.site)
		if err != nil {
			return nil, err
		}
		id, _ = res.LastInsertId()
		return []any{id}, nil
	})
}

// GateFailureRow aggregates failed logins by source address, username and proxy.
type GateFailureRow struct {
	IP       string
	Username string
	ProxyID  int64
	Attempts int
	First    time.Time
	Last     time.Time
}

// GateFailureReport lists failed logins in [from, to], newest first. Grouping
// keeps a scanning bot to one row per username rather than thousands.
func (s *Store) GateFailureReport(from, to time.Time, limit int) ([]GateFailureRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT ip, username, proxy_id, COUNT(*), MIN(ts), MAX(ts)
		FROM gate_failures WHERE ts >= ? AND ts <= ? AND (? = 0 OR site_id = ?)
		GROUP BY ip, username, proxy_id
		ORDER BY MAX(ts) DESC LIMIT ?`, stamp(from), stamp(to), s.site, s.site, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]GateFailureRow, 0, 32)
	for rows.Next() {
		var r GateFailureRow
		var first, last string
		if err := rows.Scan(&r.IP, &r.Username, &r.ProxyID, &r.Attempts, &first, &last); err != nil {
			return nil, err
		}
		r.First, r.Last = parseStamp(first), parseStamp(last)
		out = append(out, r)
	}
	return out, rows.Err()
}

// GateFailureStats returns the counts used by the escalation ladder:
// failures in the last 10 minutes, the last 24 hours, and the number of
// distinct days with failures in the last 7 days.
func (s *Store) GateFailureStats(ip string) (last10m, last24h, distinctDays int, err error) {
	now := time.Now()
	err = s.db.QueryRow(`SELECT COUNT(*) FROM gate_failures WHERE ip = ? AND ts > ? AND (? = 0 OR site_id = ?)`,
		ip, stamp(now.Add(-10*time.Minute)), s.site, s.site).Scan(&last10m)
	if err != nil {
		return
	}
	err = s.db.QueryRow(`SELECT COUNT(*) FROM gate_failures WHERE ip = ? AND ts > ? AND (? = 0 OR site_id = ?)`,
		ip, stamp(now.Add(-24*time.Hour)), s.site, s.site).Scan(&last24h)
	if err != nil {
		return
	}
	err = s.db.QueryRow(`SELECT COUNT(DISTINCT date(ts)) FROM gate_failures
		WHERE ip = ? AND ts > ? AND (? = 0 OR site_id = ?)`,
		ip, stamp(now.Add(-7*24*time.Hour)), s.site, s.site).Scan(&distinctDays)
	return
}

// ClearGateFailures removes failure history for an IP, used after a successful
// login or a manual unban.
func (s *Store) ClearGateFailures(ip string) error {
	_, err := s.deleteCaptured("gate_failures", []string{"id"}, `ip = ? AND (? = 0 OR site_id = ?)`, ip, s.site, s.site)
	return err
}

// PurgeGateFailures drops failure rows older than the retention window.
func (s *Store) PurgeGateFailures(before time.Time) error {
	_, err := s.db.Exec(`DELETE FROM gate_failures WHERE ts < ? AND (? = 0 OR site_id = ?)`,
		stamp(before), s.site, s.site)
	return err
}
