package store

import "time"

// UtilSample is one reading of host load and link rates, folded into an hour.
type UtilSample struct {
	CPU      float64
	MemUsed  int64
	MemTotal int64
	WANRx    float64
	WANTx    float64
	ProxyRx  float64
	ProxyTx  float64
}

// UtilHour is one stored hour of host and traffic utilization.
type UtilHour struct {
	Hour     time.Time `json:"hour"`
	CPU      float64   `json:"cpu"`
	MemUsed  int64     `json:"mem_used"`
	MemTotal int64     `json:"mem_total"`
	WANRx    float64   `json:"wan_rx"`
	WANTx    float64   `json:"wan_tx"`
	ProxyRx  float64   `json:"proxy_rx"`
	ProxyTx  float64   `json:"proxy_tx"`
	Reqs     int64     `json:"reqs"`
	Blocked  int64     `json:"blocked"`
}

// RollupUtilization folds one reading into its hour. Load and rates become a
// running mean of the samples taken in that hour; the request counts are
// recomputed from the events table, so an hour that is still open keeps growing
// while its rates average.
func (s *Store) RollupUtilization(now time.Time, smp UtilSample) error {
	hour := now.UTC().Truncate(time.Hour)
	end := hour.Add(time.Hour)
	if now.Before(end) {
		end = now
	}
	_, err := s.db.Exec(`INSERT INTO utilization(hour, cpu, mem_used, mem_total, wan_rx, wan_tx, proxy_rx, proxy_tx, reqs, blocked, samples)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?,
		       (SELECT COUNT(*) FROM events WHERE ts >= ? AND ts < ?),
		       (SELECT COUNT(*) FROM events WHERE ts >= ? AND ts < ? AND action IN ('block','ban','challenge')), 1)
		ON CONFLICT(hour) DO UPDATE SET
			cpu = (cpu * samples + excluded.cpu) / (samples + 1),
			mem_used = (mem_used * samples + excluded.mem_used) / (samples + 1),
			mem_total = excluded.mem_total,
			wan_rx = (wan_rx * samples + excluded.wan_rx) / (samples + 1),
			wan_tx = (wan_tx * samples + excluded.wan_tx) / (samples + 1),
			proxy_rx = (proxy_rx * samples + excluded.proxy_rx) / (samples + 1),
			proxy_tx = (proxy_tx * samples + excluded.proxy_tx) / (samples + 1),
			samples = samples + 1,
			reqs = excluded.reqs,
			blocked = excluded.blocked`,
		stamp(hour), smp.CPU, smp.MemUsed, smp.MemTotal, smp.WANRx, smp.WANTx, smp.ProxyRx, smp.ProxyTx,
		stamp(hour), stamp(end), stamp(hour), stamp(end))
	return err
}

// UtilizationHours returns the stored hours since a point in time, oldest first.
func (s *Store) UtilizationHours(since time.Time) ([]UtilHour, error) {
	rows, err := s.db.Query(`SELECT hour, cpu, mem_used, mem_total, wan_rx, wan_tx, proxy_rx, proxy_tx, reqs, blocked
		FROM utilization WHERE hour >= ? ORDER BY hour`, stamp(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UtilHour{}
	for rows.Next() {
		var u UtilHour
		var hour string
		if err := rows.Scan(&hour, &u.CPU, &u.MemUsed, &u.MemTotal, &u.WANRx, &u.WANTx, &u.ProxyRx, &u.ProxyTx,
			&u.Reqs, &u.Blocked); err != nil {
			return nil, err
		}
		u.Hour = parseStamp(hour)
		out = append(out, u)
	}
	return out, rows.Err()
}

// DeleteUtilizationBefore drops hourly rows older than the retention window.
func (s *Store) DeleteUtilizationBefore(t time.Time) error {
	_, err := s.db.Exec(`DELETE FROM utilization WHERE hour < ?`, stamp(t))
	return err
}
