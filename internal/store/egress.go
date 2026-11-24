package store

import "time"

// EgressSource is one client that was sent outbound bytes in a window.
type EgressSource struct {
	IP       string `json:"ip"`
	Country  string `json:"country"`
	ASN      int    `json:"asn"`
	Requests int64  `json:"requests"`
	BytesOut int64  `json:"bytes_out"`
}

// EgressSources ranks the clients a proxy delivered the most bytes to in a
// window, so a detection can say which addresses the data actually left for.
func (s *Store) EgressSources(proxyID int64, from, to time.Time, limit int) ([]EgressSource, error) {
	if limit <= 0 || limit > 50 {
		limit = 12
	}
	rows, err := s.db.Query(`SELECT src_ip, MAX(country), MAX(asn), COUNT(*), COALESCE(SUM(bytes_out),0)
		FROM events WHERE proxy_id = ? AND ts >= ? AND ts <= ? AND src_ip <> '' AND bytes_out > 0
		GROUP BY src_ip ORDER BY COALESCE(SUM(bytes_out),0) DESC, COUNT(*) DESC LIMIT ?`,
		proxyID, stamp(from), stamp(to), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EgressSource{}
	for rows.Next() {
		var e EgressSource
		if err := rows.Scan(&e.IP, &e.Country, &e.ASN, &e.Requests, &e.BytesOut); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
