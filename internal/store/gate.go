package store

import "time"

// RecordGateFailure logs one failed access-gate login.
func (s *Store) RecordGateFailure(ip string, proxyID int64) error {
	_, err := s.db.Exec(`INSERT INTO gate_failures(ip, proxy_id, ts) VALUES(?, ?, ?)`,
		ip, proxyID, stamp(time.Now()))
	return err
}

// GateFailureStats returns the counts used by the escalation ladder:
// failures in the last 10 minutes, the last 24 hours, and the number of
// distinct days with failures in the last 7 days.
func (s *Store) GateFailureStats(ip string) (last10m, last24h, distinctDays int, err error) {
	now := time.Now()
	err = s.db.QueryRow(`SELECT COUNT(*) FROM gate_failures WHERE ip = ? AND ts > ?`,
		ip, stamp(now.Add(-10*time.Minute))).Scan(&last10m)
	if err != nil {
		return
	}
	err = s.db.QueryRow(`SELECT COUNT(*) FROM gate_failures WHERE ip = ? AND ts > ?`,
		ip, stamp(now.Add(-24*time.Hour))).Scan(&last24h)
	if err != nil {
		return
	}
	err = s.db.QueryRow(`SELECT COUNT(DISTINCT date(ts)) FROM gate_failures WHERE ip = ? AND ts > ?`,
		ip, stamp(now.Add(-7*24*time.Hour))).Scan(&distinctDays)
	return
}

// ClearGateFailures removes failure history for an IP, used after a successful
// login or a manual unban.
func (s *Store) ClearGateFailures(ip string) error {
	_, err := s.db.Exec(`DELETE FROM gate_failures WHERE ip = ?`, ip)
	return err
}

// PurgeGateFailures drops failure rows older than the retention window.
func (s *Store) PurgeGateFailures(before time.Time) error {
	_, err := s.db.Exec(`DELETE FROM gate_failures WHERE ts < ?`, stamp(before))
	return err
}
