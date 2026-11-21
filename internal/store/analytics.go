package store

import (
	"time"
)

// AnalyticsBucket is one hour or day of request and traffic totals.
type AnalyticsBucket struct {
	Bucket   time.Time `json:"bucket"`
	Requests int64     `json:"requests"`
	Success  int64     `json:"success"`
	Errors   int64     `json:"errors"`
	BytesIn  int64     `json:"bytes_in"`
	BytesOut int64     `json:"bytes_out"`
}

// ProxyTraffic is the per-proxy share of requests and bytes for a range.
type ProxyTraffic struct {
	ProxyID  int64  `json:"proxy_id"`
	Host     string `json:"host"`
	Requests int64  `json:"requests"`
	Success  int64  `json:"success"`
	Errors   int64  `json:"errors"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
}

// Analytics is the statistical-analysis payload for one date range.
type Analytics struct {
	From      time.Time         `json:"from"`
	To        time.Time         `json:"to"`
	Totals    Totals            `json:"totals"`
	Series    []AnalyticsBucket `json:"series"`
	Proxies   []ProxyTraffic    `json:"proxies"`
	Countries []NamedCount      `json:"countries"`
	Stages    []NamedCount      `json:"stages"`
}

// AnalyticsRange aggregates requests, outcomes, traffic and visitor countries
// between two instants. It reads the event table directly, so the range is
// bounded by the configured event retention.
func (s *Store) AnalyticsRange(from, to time.Time) (Analytics, error) {
	out := Analytics{From: from, To: to, Series: []AnalyticsBucket{},
		Proxies: []ProxyTraffic{}, Countries: []NamedCount{}, Stages: []NamedCount{}}
	err := s.db.QueryRow(`SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN action IN ('block','ban','challenge') THEN 1 ELSE 0 END),0),
		COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0), COUNT(DISTINCT src_ip)
		FROM events WHERE ts >= ? AND ts <= ?`, stamp(from), stamp(to)).
		Scan(&out.Totals.Requests, &out.Totals.Blocked, &out.Totals.BytesIn, &out.Totals.BytesOut, &out.Totals.SrcIPs)
	if err != nil {
		return out, err
	}

	format := "%Y-%m-%dT%H:00:00Z"
	if to.Sub(from) > 48*time.Hour {
		format = "%Y-%m-%dT00:00:00Z"
	}
	rows, err := s.db.Query(`SELECT strftime(?, ts), COUNT(*),
		COALESCE(SUM(CASE WHEN action = 'allow' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN action IN ('block','ban','challenge') THEN 1 ELSE 0 END),0),
		COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0)
		FROM events WHERE ts >= ? AND ts <= ? GROUP BY 1 ORDER BY 1`,
		format, stamp(from), stamp(to))
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var bucket string
		var b AnalyticsBucket
		if err := rows.Scan(&bucket, &b.Requests, &b.Success, &b.Errors, &b.BytesIn, &b.BytesOut); err != nil {
			rows.Close()
			return out, err
		}
		b.Bucket = parseStamp(bucket)
		out.Series = append(out.Series, b)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return out, err
	}
	rows.Close()

	rows, err = s.db.Query(`SELECT COALESCE(proxy_id,0), COUNT(*),
		COALESCE(SUM(CASE WHEN action = 'allow' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN action IN ('block','ban','challenge') THEN 1 ELSE 0 END),0),
		COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0)
		FROM events WHERE ts >= ? AND ts <= ? GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 100`,
		stamp(from), stamp(to))
	if err != nil {
		return out, err
	}
	hosts := map[int64]string{}
	if proxies, err := s.ListProxies(); err == nil {
		for _, p := range proxies {
			hosts[p.ID] = p.Hostname
		}
	}
	for rows.Next() {
		var p ProxyTraffic
		if err := rows.Scan(&p.ProxyID, &p.Requests, &p.Success, &p.Errors, &p.BytesIn, &p.BytesOut); err != nil {
			rows.Close()
			return out, err
		}
		p.Host = hosts[p.ProxyID]
		if p.Host == "" {
			p.Host = "unmatched / blocked before routing"
		}
		out.Proxies = append(out.Proxies, p)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return out, err
	}
	rows.Close()

	out.Countries, err = s.groupCount("country", from, to, 250)
	if err != nil {
		return out, err
	}
	out.Stages, err = s.groupCount("stage", from, to, 40)
	return out, err
}

func (s *Store) groupCount(column string, from, to time.Time, limit int) ([]NamedCount, error) {
	if column != "country" && column != "stage" {
		return nil, nil
	}
	rows, err := s.db.Query(`SELECT `+column+`, COUNT(*) FROM events
		WHERE ts >= ? AND ts <= ? AND `+column+` <> ''
		GROUP BY `+column+` ORDER BY COUNT(*) DESC LIMIT ?`, stamp(from), stamp(to), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NamedCount{}
	for rows.Next() {
		var c NamedCount
		if err := rows.Scan(&c.Name, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
